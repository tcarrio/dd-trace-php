<?php

namespace DDTrace\Integrations\FS;

use DDTrace\Integrations\Integration;
use DDTrace\SpanData;
use DDTrace\Tag;
use DDTrace\Util\ObjectKVStore;

class FSIntegration extends Integration
{
    const NAME = 'fs';

    /** @var string[] $FUNCTION_NAMES */
    const FUNCTION_NAMES = [
        'basename', 'chgrp', 'chmod', 'chown', 'clearstatcache', 'copy', 'delete', 'dirname', 'disk_free_space', 'disk_total_space',
        'diskfreespace', 'fclose', 'fdatasync', 'feof', 'fflush', 'fgetc', 'fgetcsv', 'fgets', 'fgetss', 'file_exists', 'file_get_contents',
        'file_put_contents', 'file', 'fileatime', 'filectime', 'filegroup', 'fileinode', 'filemtime', 'fileowner', 'fileperms', 'filesize',
        'filetype', 'flock', 'fnmatch', 'fopen', 'fpassthru', 'fputcsv', 'fputs', 'fread', 'fscanf', 'fseek', 'fstat', 'fsync', 'ftell',
        'ftruncate', 'fwrite', 'glob', 'is_dir', 'is_executable', 'is_file', 'is_link', 'is_readable', 'is_uploaded_file', 'is_writable',
        'is_writeable', 'lchgrp', 'lchown', 'link', 'linkinfo', 'lstat', 'mkdir', 'move_uploaded_file', 'parse_ini_file', 'parse_ini_string',
        'pathinfo', 'pclose', 'popen', 'readfile', 'readlink', 'realpath_cache_get', 'realpath_cache_size', 'realpath', 'rename', 'rewind',
        'rmdir', 'set_file_buffer', 'stat', 'symlink', 'tempnam', 'tmpfile', 'touch', 'umask', 'unlink',
    ];

    /**
     * @return string The integration name.
     */
    public function getName()
    {
        return self::NAME;
    }

    /**
     * Add instrumentation to PDO requests
     */
    public function init()
    {
        if (!$this->validateFSFunctions()) {
            return Integration::NOT_AVAILABLE;
        }

        $integration = $this;

        foreach(self::FUNCTION_NAMES as $functionName) {
            $this->traceFunction($functionName, $integration);
        }

        return Integration::LOADED;
    }

    private function validateFSFunctions(): bool {
        foreach ($this->functionNames as $functionName) {
            if (!is_callable($functionName)) {
                return false;
            }
        }

        return true;
    }

    private function traceFunction(string $functionName) {
        \DDTrace\trace_function($functionName, function (SpanData $span, array $args, $retval, $exception) use ($functionName) {
            FSIntegration::setCommonSpanInfo($span);
            $span->name = $span->resource = "fs.{$functionName}";
        });
    }


    /**
     * @param PDO|PDOStatement|array $source
     * @param DDTrace\SpanData $span
     */
    public static function setCommonSpanInfo(SpanData $span)
    {
        $span->service = self::NAME;
    }
}
