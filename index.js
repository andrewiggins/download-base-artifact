import path from "path";
import { mkdir } from "fs/promises";
import prettyBytes from "pretty-bytes";
import AdmZip from "adm-zip";

/** @typedef {{ owner: string; repo: string; }} GitHubRepo */

/**
 * @param {GitHubActionClient} client
 * @param {GitHubRepo} repo
 * @param {string} ref
 * @param {Logger} logger
 * @returns {Promise<[string | undefined, string | undefined]>}
 */
export async function getGitRef(client, repo, ref, logger) {
	try {
		const sha = await client.rest.git
			.getRef({ ...repo, ref })
			.then((r) => r.data.object.sha);

		// Successfully resolved ref to sha. Return it.
		if (ref.startsWith("tags/")) {
			return [sha, undefined];
		} else {
			return [sha, ref.replace(/^heads\//, "")];
		}
	} catch (e) {
		logger.info(`Unable to resolve ref as-is: "${ref}"`);
	}

	// Try again prefixing with "heads/" for branch name
	try {
		const sha = await client.rest.git
			.getRef({ ...repo, ref: `heads/${ref}` })
			.then((r) => r.data.object.sha);

		// Successfully resolved ref to sha. Return it.
		return [sha, ref];
	} catch (e) {
		logger.info(`Unable to resolve ref as branch: "heads/${ref}"`);
	}

	// Try again prefixing with "tags/" for tag name
	try {
		const sha = await client.rest.git
			.getRef({ ...repo, ref: `tags/${ref}` })
			.then((r) => r.data.object.sha);

		// Successfully resolved ref to sha. Return it.
		return [sha, undefined];
	} catch (e) {
		logger.info(`Unable to resolve ref as tag: "tags/${ref}"`);
	}

	// Try resolving ref as a commit
	try {
		const sha = await client.rest.git
			.getCommit({
				...repo,
				commit_sha: ref,
			})
			.then((r) => r.data.sha);

		// Successfully resolve ref as a commit sha. Return it.
		return [sha, undefined];
	} catch {
		logger.info(`Unable to resolve ref as commit sha: "${ref}"`);
	}

	logger.warn(
		`Unable to resolve ref. See above logs for attempted resolutions.`,
	);
	return [undefined, undefined];
}

/**
 * @param {GitHubActionClient} client
 * @param {GitHubRepo} repo
 * @param {number} run_id
 * @returns {Promise<WorkflowData>}
 */
export async function getWorkflowFromRunId(client, repo, run_id) {
	const runResponse = await client.rest.actions.getWorkflowRun({
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
 * @returns {Promise<WorkflowData>}
 */
export async function getWorkflowFromFile(client, repo, file) {
	try {
		const res = await client.rest.actions.getWorkflow({
			...repo,
			// @ts-ignore
			workflow_id: file,
		});
		return res.data;
	} catch (e) {
		if (e.status == 404) {
			throw new Error(
				`Could not find workflow using file "${file}".\n\nFull request error details:\n${e}`,
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
 * @param {string} [ref] Branch commit should be found on
 * @returns {Promise<[WorkflowRunData | undefined, WorkflowRunData | undefined]>}
 */
export async function getWorkflowRunForCommit(
	client,
	repo,
	workflow_id,
	commit,
	ref,
) {
	/** @type {WorkflowRunData | undefined} */
	let runForCommit;
	/** @type {WorkflowRunData | undefined} */
	let lkgRun;

	// https://docs.github.com/en/rest/reference/actions#list-workflow-runs
	/** @type {Record<string, string | number>} */
	const params = { ...repo, workflow_id };
	if (ref) {
		params.branch = ref.replace(/^refs\/heads\//, "");
	}

	const endpoint = client.rest.actions.listWorkflowRuns.endpoint(params);

	/** @type {WorkflowRunsAsyncIterator} */
	const iterator = client.paginate.iterator(endpoint);
	paging: for await (const page of iterator) {
		if (page.status > 299) {
			throw new Error(
				`Non-success error code returned for workflow runs: ${page.status}`,
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
 * @returns {Promise<ArtifactData | undefined>}
 */
export async function getArtifact(client, repo, run_id, artifactName) {
	/** @type {ArtifactData | undefined} */
	let artifact;

	const endpoint = client.rest.actions.listWorkflowRunArtifacts.endpoint({
		...repo,
		run_id,
	});

	/** @type {ArtifactsAsyncIterator} */
	const iterator = client.paginate.iterator(endpoint);
	for await (let page of iterator) {
		if (page.status > 299) {
			throw new Error(
				`Non-success error code returned for listing artifacts: ${page.status}`,
			);
		}

		artifact = page.data.find((artifact) => artifact.name == artifactName);
		if (artifact) {
			break;
		}
	}

	return artifact;
}

/** @type {Logger} */
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
 * @typedef {{ workflow?: string; artifact: string; path?: string; baseRef?: string; }} Inputs
 * @typedef {{ warn(msg: string): void; info(msg: string): void; debug(getMsg: () => string): void; }} Logger
 * @typedef {GitHubActionContext["payload"]["pull_request"]} PRPayload
 *
 * @param {GitHubActionClient} octokit
 * @param {GitHubActionContext} context
 * @param {Inputs} inputs
 * @param {Logger} [log]
 */
export async function downloadBaseArtifact(
	octokit,
	context,
	inputs,
	log = defaultLogger,
) {
	const repo = context.repo;

	// 1. Determine workflow
	/** @type {WorkflowData} */
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
	/** @type {string} */
	let baseCommit;
	/** @type {string | undefined} */
	let baseRef;

	if (inputs.baseRef) {
		const [commit, ref] = await getGitRef(octokit, repo, inputs.baseRef, log);

		if (!commit) {
			throw new Error(
				`Unable to resolve base commit with inputs.baseRef: "${inputs.baseRef}"`,
			);
		}

		baseCommit = commit;
		baseRef = ref;

		if (ref) {
			log.info(`Resolved head of "${baseRef}" to commit ${baseCommit}`);
		} else {
			log.info(`Using base commit: ${baseCommit}`);
		}
	} else if (context.eventName == "push") {
		baseCommit = context.payload.before;
		baseRef = context.payload.ref;

		log.info(`Ref of push is ${baseRef}`);
		log.info(`Previous commit before push is ${baseCommit}`);
	} else if (context.eventName == "pull_request") {
		const prPayload = /** @type {NonNullable<PRPayload>} */ (
			context.payload.pull_request
		);
		baseCommit = prPayload.base.sha;
		baseRef = prPayload.base.ref;

		log.info(`Base ref of pull request is ${baseRef}`);
		log.info(`Base commit of pull request is ${baseCommit}`);
	} else if (!context.sha) {
		throw new Error(
			`No commit sha in action context (context.sha: "${context.sha}"). Current eventName is ${context.eventName}.`,
		);
	} else {
		const commit = await octokit.rest.git
			.getCommit({
				...repo,
				commit_sha: context.sha,
			})
			.then((r) => r.data);

		if (commit.parents.length == 0) {
			throw new Error(
				`No parent commits to use as a base commit. Current commit: ${context.sha}`,
			);
		}

		baseCommit = commit.parents[0].sha;
		baseRef = context.ref;

		log.info(
			`Unrecognized eventName (${context.eventName}). Using first parent commit (${baseCommit}) of current workflow commit (${context.sha})`,
		);
	}

	// 3. Determine most recent workflow run for commit
	const [commitRun, lkgRun] = await getWorkflowRunForCommit(
		octokit,
		repo,
		workflow.id,
		baseCommit,
		baseRef,
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
		`Using ${workflowRunName} (id: ${workflowRun.id}) as base workflow run`,
	);

	// 4. Download artifact for base workflow
	const artifact = await getArtifact(
		octokit,
		repo,
		workflowRun.id,
		inputs.artifact,
	);

	if (!artifact) {
		throw new Error(`Artifact "${inputs.artifact}" was not found`);
	}

	log.debug(() => "Artifact: " + JSON.stringify(artifact, null, 2));
	log.info(`Located artifact "${artifact.name}" (id: ${artifact.id})`);

	if (artifact.expired) {
		throw new Error(
			`Artifact "${artifact.name}" for workflow run ${workflowRunName} is expired. Please re-run workflow to regenerate artifacts.`,
		);
	}

	const inputPath = inputs.path ? inputs.path : ".";
	await mkdir(inputPath, { recursive: true });

	const size = prettyBytes(artifact.size_in_bytes);
	log.info(`Downloading artifact ${artifact.name}.zip (${size})...`);
	const zip = await octokit.rest.actions.downloadArtifact({
		...repo,
		artifact_id: artifact.id,
		archive_format: "zip",
	});

	log.info(`Extracting ${artifact.name}.zip...`);
	const adm = new AdmZip(Buffer.from(/**@type {any}*/ (zip.data)));
	adm.getEntries().forEach((entry) => {
		const action = entry.isDirectory ? "creating" : "inflating";
		const filepath = path.join(inputPath, entry.entryName);
		log.info(`  ${action}: ${filepath}`);
	});

	adm.extractAllTo(inputPath, true);
}
