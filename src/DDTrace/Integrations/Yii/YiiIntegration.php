<?php

namespace DDTrace\Integrations\Yii;

use DDTrace\Contracts\Scope;
use DDTrace\GlobalTracer;
use DDTrace\Integrations\Integration;
use DDTrace\SpanData;
use DDTrace\Tag;
use DDTrace\Type;
use DDTrace\Util\Versions;
use yii\helpers\Url;

class YiiIntegration extends Integration
{
    const NAME = 'yii';

    /**
     * @return string The integration name.
     */
    public function getName()
    {
        return self::NAME;
    }

    /**
     * {@inheritdoc}
     */
    public function requiresExplicitTraceAnalyticsEnabling()
    {
        return false;
    }

    /**
     * {@inheritdoc}
     */
    public function init()
    {
        // This is eagerly loaded on 5, and deferred on 7+
        if (\PHP_MAJOR_VERSION === 5) {
            $integration = $this;
            \DDTrace\hook_method(
                "yii\\di\\Container",
                "__construct",
                null,
                function () use ($integration) {
                    $integration->load();
                }
            );
            return self::LOADED;
        } else {
            return $this->load();
        }
    }

    private function load()
    {
        if (Versions::versionMatches('2.0', \Yii::getVersion())) {
            return $this->load_v2();
        }
        return self::NOT_LOADED;
    }

    private function load_v2()
    {
        $scope = GlobalTracer::get()->getRootScope();
        if (!$scope instanceof Scope) {
            return self::NOT_LOADED;
        }

        $root = $scope->getSpan();
        $this->addTraceAnalyticsIfEnabledLegacy($root);
        $service = \ddtrace_config_app_name(self::NAME);

        \DDTrace\trace_method(
            'yii\web\Application',
            'run',
            function (SpanData $span) use ($service) {
                $span->name = $span->resource = \get_class($this) . '.run';
                $span->type = Type::WEB_SERVLET;
                $span->service = $service;
            }
        );

        // We assume the first controller is the one to assign to app.endpoint
        $firstController = null;
        \DDTrace\hook_method(
            'yii\web\Application',
            'createController',
            null,
            function ($unused1, $unused2, $args, $retval) use (&$firstController) {
                if ($firstController == null && isset($args[0], $retval) && \is_array($retval) && !empty($retval)) {
                    $firstController = $retval[0];
                }
            }
        );

        /* Note that Applications are Modules, so this will also trace
         * Application::runAction, but modules are worth tracing
         * independently, as multiple modules can trigger per application,
         * such as in the event of an unhandled exception.
         */
        \DDTrace\trace_method(
            'yii\base\Module',
            'runAction',
            function (SpanData $span, $args) use ($service) {
                $span->name = \get_class($this) . '.runAction';
                $span->type = Type::WEB_SERVLET;
                $span->service = $service;
                $span->resource = isset($args[0]) && is_string($args[0]) ? $args[0] : $span->name;
            }
        );

        \DDTrace\trace_method(
            'yii\base\Controller',
            'runAction',
            function (SpanData $span, $args) use (&$firstController, $service, $root) {
                $span->name = \get_class($this) . '.runAction';
                $span->type = Type::WEB_SERVLET;
                $span->service = $service;
                $span->resource = isset($args[0]) && is_string($args[0]) ? $args[0] : $span->name;

                if (
                    $firstController === $this
                    && $root->getTag('app.endpoint') === null
                    && isset($this->action->actionMethod)
                ) {
                    $controller = \get_class($this);
                    $endpoint = "{$controller}::{$this->action->actionMethod}";
                    $root->setTag("app.endpoint", $endpoint);
                    $root->setTag(Tag::HTTP_URL, Url::base(true) . Url::current());
                }

                if ($root->getTag('app.route.path') === null) {
                    $route = $this->module->requestedRoute;
                    $namedParams = [$route];
                    $placeholders = [$route];
                    if (isset($args[1]) && \is_array($args[1]) && !empty($args[1])) {
                        foreach ($args[1] as $param => $unused) {
                            $namedParams[$param] = ":{$param}";
                            $placeholders[$param] = '?';
                        }
                    }

                    $routePath = \urldecode(Url::toRoute($namedParams));
                    $root->setTag('app.route.path', $routePath);

                    $resourceName = \urldecode(Url::toRoute($placeholders));
                    $root->setTag(Tag::RESOURCE_NAME, "{$_SERVER['REQUEST_METHOD']} {$resourceName}", true);
                }
            }
        );

        \DDTrace\trace_method(
            'yii\base\View',
            'renderFile',
            function (SpanData $span, $args) use ($service) {
                $span->name = \get_class($this) . '.renderFile';
                $span->type = Type::WEB_SERVLET;
                $span->service = $service;
                $span->resource = isset($args[0]) && is_string($args[0]) ? $args[0] : $span->name;
            }
        );

        return self::LOADED;
    }
}
