
/////////////////////////////////////////////////////////////////////////
// wcjswrap-test-node.js
//
// This file is intended to sit between the c-code (wcjs.c) and
// any javascript development
//
/////////////////////////////////////////////////////////////////////////

var fs = require('fs');
var wc = require('./wcjs-node.js');

eval(fs.readFileSync('./wcjswrap.js').toString());
eval(fs.readFileSync('./wcjswrap-test.js').toString());

entry_point();
