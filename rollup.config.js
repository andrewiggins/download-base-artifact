import commonjs from "@rollup/plugin-commonjs";
import json from "@rollup/plugin-json";
import nodeResolve from "@rollup/plugin-node-resolve";
import nodeExternals from "rollup-plugin-node-externals";

export default {
	input: "action.js",
	output: {
		file: "dist/action.js",
		format: "esm",
	},
	plugins: [
		json({
			compact: true,
			preferConst: true,
		}),
		commonjs({
			// Ignore Electron support in adm-zip
			ignore: ["original-fs"],
		}),
		nodeResolve({
			// Since we know we are building for a node env, prefer exports.node over
			// others if specified by a package (e.g. uuid)
			exportConditions: ["node", "default", "module", "import"],
		}),
		nodeExternals({
			deps: false,
		}),
	],
};
