import core from "@actions/core";
import github from "@actions/github";

/**
 * @param {GitHubClient} octokit
 * @param {GitHubContext} context
 * @param {Inputs} inputs
 */
async function run(octokit, context, inputs) {
  console.log("Inputs:", inputs);
  console.log("Context:", JSON.stringify(context, undefined, 2));
}

(async () => {
  try {
    const token = core.getInput("github_token", { required: true });
    const workflow = core.getInput("workflow", { required: false });
    const artifact = core.getInput("artifact", { required: true });
    const path = core.getInput("path", { required: false });

    const octokit = github.getOctokit(token);
    await run(octokit, github.context, {
      workflow,
      artifact,
      path,
    });
  } catch (e) {
    core.setFailed(e.message);
  }
})();
