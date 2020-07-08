import core from "@actions/core";
import github from "@actions/github";

try {
  const workflow = core.getInput("workflow", { required: false });
  const artifact = core.getInput("artifact", { required: true });
  const path = core.getInput("path", { required: false });

  console.log("Options:", { workflow, artifact, path });

  // Get the JSON webhook payload for the event that triggered the workflow
  const payload = JSON.stringify(github.context.payload, undefined, 2);
  console.log(`The event payload: ${payload}`);
} catch (error) {
  core.setFailed(error.message);
}
