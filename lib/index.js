/**
 * @param {GitHubClient} client
 * @param {GitHubContext} context
 * @param {number} run_id
 * @returns {Promise<WorkflowData>}
 */
async function getWorkflowFromRunId(client, context, run_id) {
	const runResponse = await client.actions.getWorkflowRun({
		...context.repo,
		run_id,
	});

	const workflowRes = await client.request({
		url: runResponse.data.workflow_url,
	});

	return workflowRes.data;
}

/**
 * @param {GitHubClient} client
 * @param {GitHubContext} context
 * @param {string} file
 * @returns {Promise<WorkflowData>}
 */
async function getWorkflowFromFile(client, context, file) {
	try {
		const res = await client.actions.getWorkflow({
			...context.repo,
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
 * @param {GitHubClient} client
 * @param {GitHubRepo} repo
 * @param {number} workflow_id
 * @param {string} commit
 * @param {string} [ref]
 * @returns {Promise<WorkflowRunData | null>}
 */
async function getWorkflowRunForCommit(client, repo, workflow_id, commit, ref) {
	// https://docs.github.com/en/rest/reference/actions#list-workflow-runs

	/** @type {Record<string, string | number>} */
	const params = { ...repo, workflow_id, status: "success" };
	if (ref) {
		params.branch = ref.replace(/^refs\/heads\//, "");
	}

	const endpoint = client.actions.listWorkflowRuns.endpoint(params);

	/** @type {WorkflowRunsAsyncIterator} */
	const iterator = client.paginate.iterator(endpoint);

	let run = null;
	for await (const res of iterator) {
		if (res.status > 299) {
			throw new Error(
				`Non-success error code returned for workflow runs: ${res.status}`
			);
		}

		run = res.data.find((run) => run.head_sha == commit);
		if (run) {
			break;
		}
	}

	return run;
}

module.exports = {
	getWorkflowFromRunId,
	getWorkflowFromFile,
	getWorkflowRunForCommit,
};
