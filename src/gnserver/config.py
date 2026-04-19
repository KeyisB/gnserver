

import logging
import sys

logConfig = {
    'level': 'DEBUG',
    'loggers': {
        'GNServer': {
            'level': 'DEBUG'
        },
        'GNServer.DatagramEndpoint': {
            'level': 'DEBUG'
        },
        "GNServer.Client": {
            'level': 'DEBUG'
        },
        "GNServer.DatagramEndpoint.KDC": {
            'level': 'DEBUG'
        },
        "GNServer.DatagramEndpoint.PQ": {
            'level': 'DEBUG'
        }
    }
}

def update_log_config(config: dict):
    for logger_name, logger_config in config.get('loggers', {}).items():
        if isinstance(logger_config, dict):
            if logger_name in logConfig['loggers']:
                logConfig['loggers'][logger_name].update(logger_config)
            else:
                logConfig['loggers'][logger_name] = logger_config
    
    l = logConfig.get('level')
    if l is not None:
        for logger_name in logConfig['loggers']:
            logConfig['loggers'][logger_name]['level'] = l # type: ignore

    rebuild_log_config()

def rebuild_log_config():
    formatter = logging.Formatter(
        "[%(asctime)s] [%(name)s] %(levelname)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )
    console = logging.StreamHandler(sys.stdout)
    console.setLevel(logging.DEBUG)
    console.setFormatter(formatter)


    for logger_name, logger_config in logConfig.get('loggers', {}).items():
        logger = logging.getLogger(logger_name)
        level_str = logger_config.get('level', 'INFO')
        level = getattr(logging, level_str.upper(), logging.INFO)
        logger.setLevel(level)


        
        logger.propagate = False
        if logger.hasHandlers():
            logger.handlers.clear()

        logger.addHandler(console)

rebuild_log_config()