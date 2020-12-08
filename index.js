const path = require("path");
const { mkdir } = require("fs").promises;
const prettyBytes = require("pretty-bytes");
const AdmZip = require("adm-zip");

/** @typedef {{ owner: string; repo: string; }} GitHubRepo */

/**
 * @param {GitHubActionClient} client
 * @param {GitHubRepo} repo
 * @param {number} run_id
 * @returns {Promise<import('./global').WorkflowData>}
 */
async function getWorkflowFromRunId(client, repo, run_id) {
	const runResponse = await client.actions.getWorkflowRun({
		...repo,
		run_id,
	});

	const workflowRes = await client.request({
		url: runResponse.data.workflow_url,
	});

	return workflowRes.data;
}

/**
 * @param {GitHubActionClient} client
 * @param {GitHubRepo} repo
 * @param {string} file
 * @returns {Promise<import('./global').WorkflowData>}
 */
async function getWorkflowFromFile(client, repo, file) {
	try {
		const res = await client.actions.getWorkflow({
			...repo,
			// @ts-ignore
			workflow_id: file,
		});
		return res.data;
	} catch (e) {
		if (e.status == 404) {
			throw new Error(
				`Could not find workflow using file "${file}".\n\nFull request error details:\n${e}`
			);
		} else {
			throw e;
		}
	}
}

/**
 * @param {GitHubActionClient} client
 * @param {GitHubRepo} repo
 * @param {number} workflow_id The ID of the workflow whose runs to search
 * @param {string} commit Commit to look for a workflow run
 * @param {string} ref Branch commit should be found on
 * @returns {Promise<[import('./global').WorkflowRunData | undefined, import('./global').WorkflowRunData]>}
 */
async function getWorkflowRunForCommit(client, repo, workflow_id, commit, ref) {
	/** @type {import('./global').WorkflowRunData} */
	let runForCommit, lkgRun;

	// https://docs.github.com/en/rest/reference/actions#list-workflow-runs
	/** @type {Record<string, string | number>} */
	const params = { ...repo, workflow_id };
	if (ref) {
		params.branch = ref.replace(/^refs\/heads\//, "");
	}

	const endpoint = client.actions.listWorkflowRuns.endpoint(params);

	/** @type {import('./global').WorkflowRunsAsyncIterator} */
	const iterator = client.paginate.iterator(endpoint);
	paging: for await (const page of iterator) {
		if (page.status > 299) {
			throw new Error(
				`Non-success error code returned for workflow runs: ${page.status}`
			);
		}

		for (let run of page.data) {
			// Get the last successful workflow run for the base ref
			if (lkgRun == null && run.conclusion == "success") {
				lkgRun = run;
			}

			if (runForCommit == null && run.head_sha == commit) {
				runForCommit = run;
			}

			if (runForCommit && lkgRun) {
				break paging;
			}
		}
	}

	return [runForCommit, lkgRun];
}

/**
 * @param {GitHubActionClient} client
 * @param {GitHubRepo} repo
 * @param {number} run_id
 * @param {string} artifactName
 * @returns {Promise<import('./global').ArtifactData | undefined>}
 */
async function getArtifact(client, repo, run_id, artifactName) {
	/** @type {import('./global').ArtifactData} */
	let artifact;

	const endpoint = client.actions.listWorkflowRunArtifacts.endpoint({
		...repo,
		run_id,
	});

	/** @type {import('./global').ArtifactsAsyncIterator} */
	const iterator = client.paginate.iterator(endpoint);
	for await (let page of iterator) {
		if (page.status > 299) {
			throw new Error(
				`Non-success error code returned for listing artifacts: ${page.status}`
			);
		}

		artifact = page.data.find((artifact) => artifact.name == artifactName);
		if (artifact) {
			break;
		}
	}

	return artifact;
}

const defaultLogger = {
	warn(getMsg) {
		console.warn(getMsg);
	},
	info(getMsg) {
		console.log(getMsg);
	},
	debug() {},
};

/**
 * @typedef {ReturnType<typeof import('@actions/github').getOctokit>} GitHubActionClient
 * @typedef {typeof import('@actions/github').context} GitHubActionContext
 * @typedef {{ workflow?: string; artifact: string; path?: string; }} Inputs
 * @typedef {{ warn(msg: string): void; info(msg: string): void; debug(getMsg: () => string): void; }} Logger
 *
 * @param {GitHubActionClient} octokit
 * @param {GitHubActionContext} context
 * @param {Inputs} inputs
 * @param {Logger} [log]
 */
async function downloadBaseArtifact(
	octokit,
	context,
	inputs,
	log = defaultLogger
) {
	const repo = context.repo;

	// 1. Determine workflow
	/** @type {import('./global').WorkflowData} */
	let workflow;
	if (inputs.workflow) {
		log.info(`Trying to get workflow matching "${inputs.workflow}"...`);
		workflow = await getWorkflowFromFile(octokit, repo, inputs.workflow);
	} else {
		log.info(`Trying to get workflow of current run (id: ${context.runId})...`);
		workflow = await getWorkflowFromRunId(octokit, repo, context.runId);
	}

	log.debug(() => `Workflow: ${JSON.stringify(workflow, null, 2)}`);
	log.info(`Resolved to "${workflow.name}" (id: ${workflow.id})`);

	// 2. Determine base commit
	let baseCommit, baseRef;
	if (context.eventName == "push") {
		baseCommit = context.payload.before;
		baseRef = context.payload.ref;

		log.info(`Ref of push is ${baseRef}`);
		log.info(`Previous commit before push is ${baseCommit}`);
	} else if (context.eventName == "pull_request") {
		baseCommit = context.payload.pull_request.base.sha;
		baseRef = context.payload.pull_request.base.ref;

		log.info(`Base ref of pull request is ${baseRef}`);
		log.info(`Base commit of pull request is ${baseCommit}`);
	} else {
		throw new Error(
			`Unsupported eventName in github.context: ${context.eventName}`
		);
	}

	// 3. Determine most recent workflow run for commit
	const [commitRun, lkgRun] = await getWorkflowRunForCommit(
		octokit,
		repo,
		workflow.id,
		baseCommit,
		baseRef
	);

	log.debug(() => `Commit Run: ${JSON.stringify(commitRun, null, 2)}`);
	log.debug(() => `LKG Run: ${JSON.stringify(lkgRun, null, 2)}`);

	let workflowRun,
		warningMessage = "";
	if (commitRun && commitRun.conclusion == "success") {
		workflowRun = commitRun;
	} else {
		if (!commitRun) {
			warningMessage += `Could not find workflow run for ${baseCommit}.`;
		} else if (commitRun.conclusion !== "success") {
			warningMessage += `Workflow run for ${baseCommit} (${workflow.name}#${commitRun.run_number}) was not successful. Conclusion was "${commitRun.conclusion}".`;
		}

		if (lkgRun) {
			warningMessage += ` Using last successful run for ${baseRef}: ${workflow.name}#${lkgRun.run_number} (id: ${lkgRun.id})`;
			workflowRun = lkgRun;
		} else {
			warningMessage += ` Could not find any successful workflow run for ${baseRef} to fall back to.`;
		}
	}

	if (warningMessage !== "") {
		log.warn(warningMessage);
	}

	if (!workflowRun) {
		const params = JSON.stringify({
			workflowId: workflow.id,
			baseCommit,
			baseRef,
			status: "success",
		});
		throw new Error(`Could not find workflow run matching ${params}`);
	}

	const workflowRunName = `${workflow.name}#${workflowRun.run_number}`;
	log.info(
		`Using ${workflowRunName} (id: ${workflowRun.id}) as base workflow run`
	);

	// 4. Download artifact for base workflow
	const artifact = await getArtifact(
		octokit,
		repo,
		workflowRun.id,
		inputs.artifact
	);

	if (!artifact) {
		throw new Error(`Artifact "${inputs.artifact}" was not found`);
	}

	log.debug(() => "Artifact: " + JSON.stringify(artifact, null, 2));
	log.info(`Located artifact "${artifact.name}" (id: ${artifact.id})`);

	if (artifact.expired) {
		throw new Error(
			`Artifact "${artifact.name}" for workflow run ${workflowRunName} is expired. Please re-run workflow to regenerate artifacts.`
		);
	}

	if (!inputs.path) {
		inputs.path = ".";
	}

	await mkdir(inputs.path, { recursive: true });

	const size = prettyBytes(artifact.size_in_bytes);
	log.info(`Downloading artifact ${artifact.name}.zip (${size})...`);
	const zip = await octokit.actions.downloadArtifact({
		...repo,
		artifact_id: artifact.id,
		archive_format: "zip",
	});

	log.info(`Extracting ${artifact.name}.zip...`);
	const adm = new AdmZip(Buffer.from(zip.data));
	adm.getEntries().forEach((entry) => {
		const action = entry.isDirectory ? "creating" : "inflating";
		const filepath = path.join(inputs.path, entry.entryName);
		log.info(`  ${action}: ${filepath}`);
	});

	adm.extractAllTo(inputs.path, true);
}

module.exports = {
	getWorkflowFromFile,
	getWorkflowFromRunId,
	getWorkflowRunForCommit,
	getArtifact,
	downloadBaseArtifact,
};
