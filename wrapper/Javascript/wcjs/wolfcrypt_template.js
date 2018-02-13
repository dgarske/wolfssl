/* wolfCrypt */

/* emscripten module handlers */
var Module = {
	'print':    function(text) { console.log('stdout: ' + text) },
	'printErr': function(text) { console.log('stderr: ' + text) },
};

/* wolfCrypt */
VAR_WCJS_ASM_JS

/* wcjs emscripten engine */
VAR_WCJS_JS


/* wcjs test code */
var wc = Module
VAR_WCJSWRAP_JS
VAR_WCJSWRAP_TEST_JS
