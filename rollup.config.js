const commonjs = require("@rollup/plugin-commonjs");
const { nodeResolve } = require("@rollup/plugin-node-resolve");
const nodeExternals = require("rollup-plugin-node-externals");

module.exports = {
	input: "index.js",
	output: {
		file: "dist/index.js",
		format: "cjs",
	},
	plugins: [nodeResolve(), commonjs(), nodeExternals()],
};
