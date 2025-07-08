"""
HTTP API for Proxmox VE prometheus collector.
"""

import logging
import time
from functools import partial

import gunicorn.app.base
from prometheus_client import CONTENT_TYPE_LATEST, Summary, Counter, generate_latest
from werkzeug.routing import Map, Rule
from werkzeug.wrappers import Request, Response
from werkzeug.exceptions import InternalServerError
from pve_exporter.collector import collect_pve


class PveExporterApplication:
    """
    Proxmox VE prometheus collector HTTP handler.
    """

    def __init__(self, config, duration, errors, collectors):
        self._config = config
        self._duration = duration
        self._errors = errors
        self._collectors = collectors

        self._log = logging.getLogger(__name__)

    def on_pve(self, module="default", target="localhost", cluster="1", node="1"):
        """
        Request handler for /pve route
        """
        self._log.info(
            f"on_pve called: module='{module}', target='{target}', cluster='{cluster}', node='{node}'"
        )
        self._log.debug(f"Available modules: {list(self._config.keys())}")

        if module in self._config:
            self._log.info(f"Using module '{module}' config: {self._config[module]}")
            start = time.time()
            try:
                output = collect_pve(
                    self._config[module],
                    target,
                    cluster.lower() not in ["false", "0", ""],
                    node.lower() not in ["false", "0", ""],
                    self._collectors,
                )
                response = Response(output)
                response.headers["content-type"] = CONTENT_TYPE_LATEST
                duration = time.time() - start
                self._duration.labels(module).observe(duration)
                self._log.info(
                    f"Collection successful for module '{module}' in {duration:.2f}s"
                )
            except Exception as e:
                self._log.exception(
                    f"Error collecting metrics for module '{module}': {e}"
                )
                raise
        else:
            self._log.error(
                f"Module '{module}' not found in config. Available: {list(self._config.keys())}"
            )
            response = Response(f"Module '{module}' not found in config")
            response.status_code = 400

        return response

    def on_metrics(self):
        """
        Request handler for /metrics route
        """
        self._log.debug("on_metrics called")

        response = Response(generate_latest())
        response.headers["content-type"] = CONTENT_TYPE_LATEST

        return response

    def on_index(self):
        """
        Request handler for index route (/).
        """
        self._log.debug("on_index called")

        response = Response(
            """<html>
            <head><title>Proxmox VE Exporter</title></head>
            <body>
            <h1>Proxmox VE Exporter</h1>
            <p>Visit <code>/pve?target=1.2.3.4</code> to use.</p>
            </body>
            </html>"""
        )
        response.headers["content-type"] = "text/html"

        return response

    def view(self, endpoint, values, args):
        """
        Werkzeug views mapping method.
        """
        self._log.debug(
            f"view called: endpoint='{endpoint}', values={values}, args={args}"
        )

        allowed_args = {"pve": ["module", "target", "cluster", "node"]}

        view_registry = {
            "index": self.on_index,
            "metrics": self.on_metrics,
            "pve": self.on_pve,
        }

        params = dict(values)
        if endpoint in allowed_args:
            params.update(
                {key: args[key] for key in allowed_args[endpoint] if key in args}
            )

        try:
            self._log.debug(f"Calling {endpoint} with params: {params}")
            return view_registry[endpoint](**params)
        except Exception as error:  # pylint: disable=broad-except
            self._log.exception("Exception thrown while rendering view")
            self._errors.labels(args.get("module", "default")).inc()
            raise InternalServerError from error

    @Request.application
    def __call__(self, request):
        self._log.info(
            f"HTTP Request: {request.method} {request.path}?{request.query_string.decode()}"
        )

        url_map = Map(
            [
                Rule("/", endpoint="index"),
                Rule("/metrics", endpoint="metrics"),
                Rule("/pve", endpoint="pve"),
            ]
        )

        urls = url_map.bind_to_environ(request.environ)
        view_func = partial(self.view, args=request.args)
        return urls.dispatch(view_func, catch_http_exceptions=True)


class StandaloneGunicornApplication(gunicorn.app.base.BaseApplication):
    """
    Copy-paste from https://docs.gunicorn.org/en/stable/custom.html
    """

    # 'init' and 'load' methods are implemented by WSGIApplication.
    # pylint: disable=abstract-method

    def __init__(self, app, options=None):
        self.options = options or {}
        self.application = app
        super().__init__()

    def load_config(self):
        config = {
            key: value
            for key, value in self.options.items()
            if key in self.cfg.settings and value is not None
        }
        for key, value in config.items():
            self.cfg.set(key.lower(), value)

    def load(self):
        return self.application


def start_http_server(config, gunicorn_options, collectors):
    """
    Start a HTTP API server for Proxmox VE prometheus collector.
    """
    logger = logging.getLogger(__name__)
    logger.info(f"Starting HTTP server with config modules: {list(config.keys())}")
    logger.debug(f"Gunicorn options: {gunicorn_options}")

    duration = Summary(
        "pve_collection_duration_seconds",
        "Duration of collections by the PVE exporter",
        ["module"],
    )
    errors = Counter(
        "pve_request_errors_total",
        "Errors in requests to PVE exporter",
        ["module"],
    )

    # Initialize metrics.
    for module in config.keys():
        # pylint: disable=no-member
        errors.labels(module)
        # pylint: disable=no-member
        duration.labels(module)

    app = PveExporterApplication(config, duration, errors, collectors)
    StandaloneGunicornApplication(app, gunicorn_options).run()
