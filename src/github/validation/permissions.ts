import * as core from "@actions/core";
import type { ParsedGitHubContext } from "../context";
import type { Octokit } from "@octokit/rest";

/**
 * Check if the actor has write permissions to the repository
 * @param octokit - The Octokit REST client
 * @param context - The GitHub context
 * @param allowedNonWriteUsers - Comma-separated list of users allowed without write permissions, or '*' for all
 * @param githubTokenProvided - Whether github_token was provided as input (not from app)
 * @returns true if the actor has write permissions, false otherwise
 */
export async function checkWritePermissions(
  octokit: Octokit,
  context: ParsedGitHubContext,
  allowedNonWriteUsers?: string,
  githubTokenProvided?: boolean,
): Promise<boolean> {
  const { repository, actor } = context;
  const serverUrl =
    process.env.GITHUB_SERVER_URL ||
    process.env.GITEA_SERVER_URL ||
    "https://github.com";
  const isGitHubDotCom = serverUrl === "https://github.com";

  try {
    core.info(`Checking permissions for actor: ${actor}`);

    // Check if we should bypass permission checks for this user
    if (allowedNonWriteUsers && githubTokenProvided) {
      const allowedUsers = allowedNonWriteUsers.trim();
      if (allowedUsers === "*") {
        core.warning(
          `⚠️ SECURITY WARNING: Bypassing write permission check for ${actor} due to allowed_non_write_users='*'. This should only be used for workflows with very limited permissions.`,
        );
        return true;
      } else if (allowedUsers) {
        const allowedUserList = allowedUsers
          .split(",")
          .map((u) => u.trim())
          .filter((u) => u.length > 0);
        if (allowedUserList.includes(actor)) {
          core.warning(
            `⚠️ SECURITY WARNING: Bypassing write permission check for ${actor} due to allowed_non_write_users configuration. This should only be used for workflows with very limited permissions.`,
          );
          return true;
        }
      }
    }

    // Check if the actor is a GitHub App (bot user)
    if (actor.endsWith("[bot]")) {
      core.info(`Actor is a GitHub App: ${actor}`);
      return true;
    }

    let response: { data: { permission: string } };
    try {
      // Check permissions directly using the permission endpoint
      response = await octokit.repos.getCollaboratorPermissionLevel({
        owner: repository.owner,
        repo: repository.repo,
        username: actor,
      });
    } catch (error: any) {
      // Some Gitea setups return 403 for this endpoint even for valid users.
      if (!isGitHubDotCom && error?.status === 403) {
        if (actor === repository.owner) {
          core.warning(
            `Permission endpoint returned 403 on ${serverUrl}; allowing repository owner '${actor}' to proceed.`,
          );
          return true;
        }
        core.warning(
          `Permission endpoint returned 403 on ${serverUrl}; blocking non-owner actor '${actor}'. Configure allowed_non_write_users to override if needed.`,
        );
        return false;
      }
      throw error;
    }

    const permissionLevel = response.data.permission;
    core.info(`Permission level retrieved: ${permissionLevel}`);

    if (permissionLevel === "admin" || permissionLevel === "write") {
      core.info(`Actor has write access: ${permissionLevel}`);
      return true;
    } else {
      core.warning(`Actor has insufficient permissions: ${permissionLevel}`);
      return false;
    }
  } catch (error) {
    core.error(`Failed to check permissions: ${error}`);
    throw new Error(`Failed to check permissions for ${actor}: ${error}`);
  }
}
