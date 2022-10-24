import commonjs from "@rollup/plugin-commonjs";
import nodeResolve from "@rollup/plugin-node-resolve";
import nodeExternals from "rollup-plugin-node-externals";

export default {
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
