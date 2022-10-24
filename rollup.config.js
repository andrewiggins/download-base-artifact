const commonjs = require("@rollup/plugin-commonjs");
const { nodeResolve } = require("@rollup/plugin-node-resolve");
const { default: nodeExternals } = require("rollup-plugin-node-externals");

module.exports = {
	input: "action.js",
	output: {
		file: "dist/action.js",
		format: "esm",
	},
	plugins: [
		commonjs({
			// Ignore Electron support in adm-zip
			ignore: ["original-fs"],
		}),
		nodeResolve(),
		nodeExternals({
			deps: false,
		}),
	],
};
