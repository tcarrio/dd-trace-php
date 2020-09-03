--TEST--
Check if ddtrace8 is loaded
--SKIPIF--
<?php
if (!extension_loaded('ddtrace8')) {
	echo 'skip';
}
?>
--FILE--
<?php
echo 'The extension "ddtrace8" is available';
?>
--EXPECT--
The extension "ddtrace8" is available
