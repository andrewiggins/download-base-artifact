import core from "@actions/core";
import github from "@actions/github";
import { downloadBaseArtifact } from "./index.js";

(async () => {
	let required = true;

	try {
		const token = core.getInput("github_token", { required: true });
		const workflow = core.getInput("workflow", { required: false });
		const artifact = core.getInput("artifact", { required: true });
		const path = core.getInput("path", { required: false });
		required =
			core.getInput("required", { required: false })?.toLowerCase() === "true";
		const baseRef = core.getInput("baseRef", { required: false });

		const octokit = github.getOctokit(token);
		const inputs = { workflow, artifact, path, baseRef };

		core.debug("Required: " + required);
		core.debug("Inputs: " + JSON.stringify(inputs, null, 2));
		core.debug("Context: " + JSON.stringify(github.context, undefined, 2));

		/** @type {import ('./index.js').Logger} */
		const actionLogger = {
			warn(msg) {
				core.warning(msg);
			},
			info(msg) {
				core.info(msg);
			},
			debug(getMsg) {
				core.debug(getMsg());
			},
		};

		await downloadBaseArtifact(octokit, github.context, inputs, actionLogger);
	} catch (e) {
		if (required) {
			core.setFailed(e.message);
		} else {
			core.info(
				`Error was thrown but "required" input is set to false so ignoring it. See below for error.`,
			);
			core.info(e.toString());
		}
	}
})();
