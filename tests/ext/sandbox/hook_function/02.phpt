--TEST--
DDTrace\hook_function returns false quietly when no hook is passed
--ENV--
DD_TRACE_DEBUG=0
--FILE--
<?php
use DDTrace\SpanData;

var_dump(DDTrace\hook_function('greet'));

function greet($name)
{
    echo "Hello, {$name}.\n";
}

greet('Datadog');

?>
--EXPECT--
bool(false)
Hello, Datadog.
