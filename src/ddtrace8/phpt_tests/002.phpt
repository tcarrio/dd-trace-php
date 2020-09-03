--TEST--
test1() Basic test
--SKIPIF--
<?php if (!extension_loaded('ddtrace8')) echo 'skip'; ?>
--FILE--
<?php

dd_trace_noop();

echo "Done.\n";
?>
--EXPECT--
Done.

