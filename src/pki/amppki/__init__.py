from pyramid.config import Configurator

def main(global_config, **settings):
    config = Configurator(settings=settings)
    config.include("pyramid_chameleon")
    config.include("pyramid_assetviews")

    config.add_asset_views('amppki:static', filenames=['robots.txt'], http_cache=3600)

    config.add_route("sign", "sign")
    config.add_route("cert", "cert/{ampname}/{signature}")

    config.add_route("default", "/*args")

    config.scan()
    return config.make_wsgi_app()
