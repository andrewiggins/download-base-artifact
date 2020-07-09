/**
 * @param {GitHubClient} client
 * @param {GitHubContext} context
 * @param {number} run_id
 */
export async function getWorkflowIdFromRunId(client, context, run_id) {
	const res = await client.actions.getWorkflowRun({ ...context.repo, run_id });
	return res.data.workflow_id;
}

/**
 * @param {GitHubClient} client
 * @param {GitHubContext} context
 * @param {string} file
 */
export async function getWorkflowIdFromFile(client, context, file) {
	try {
		const res = await client.actions.getWorkflow({
			...context.repo,
			workflow_id: file,
		});
		return res.data.id;
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
