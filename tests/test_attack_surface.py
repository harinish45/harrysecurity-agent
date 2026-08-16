from nexus.analysis import Asset, AttackSurface, Service


def test_attack_surface_merges_assets_deterministically():
    surface = AttackSurface()
    surface.add(Asset("WEB01", hostname="web01.example", addresses=("10.0.0.1",), technologies=("nginx",)))
    surface.add(Asset("web01", addresses=("10.0.0.2",), services=(Service("tcp", 443, "https", exposure="external"),), technologies=("python",)))

    asset = surface.get("web01")
    assert asset is not None
    assert asset.addresses == ("10.0.0.1", "10.0.0.2")
    assert asset.technologies == ("nginx", "python")
    assert len(surface.exposed_services()) == 1


def test_attack_surface_rejects_empty_asset_id():
    surface = AttackSurface()
    try:
        surface.add(Asset(""))
    except ValueError as exc:
        assert "asset_id" in str(exc)
    else:
        raise AssertionError("empty asset id should fail closed")
