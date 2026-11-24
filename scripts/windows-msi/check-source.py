"""Validate the release invariants of our hand-maintained WiX definition."""
from pathlib import Path
import tomllib
import xml.etree.ElementTree as ET

root = Path(__file__).resolve().parents[2]
workspace = tomllib.loads((root / 'Cargo.toml').read_text())
package = tomllib.loads((root / 'crates/depscan-cli/Cargo.toml').read_text())
ns = {'w': 'http://schemas.microsoft.com/wix/2006/wi'}
product = ET.parse(root / 'crates/depscan-cli/wix/main.wxs').getroot().find('w:Product', ns)
wix = package['package']['metadata']['wix']

def require(condition, message):
    if not condition:
        raise SystemExit('MSI source contract: ' + message)

require(product is not None, 'missing Product')
require(product.get('Name') == package['package']['name'], 'product/package name mismatch')
require(product.get('Version') == '$(var.Version)', 'version must come from cargo-wix')
require(product.get('UpgradeCode').upper() == wix['upgrade-guid'].upper(), 'upgrade identity drift')
component = product.find(".//w:Component[@Id='Path']", ns)
require(component is not None and component.get('Guid').upper() == wix['path-guid'].upper(), 'PATH component identity drift')
require(product.find('w:MajorUpgrade', ns).get('Schedule') == 'afterInstallExecute', 'upgrade must precede final type restoration')
require(set(workspace['workspace']['metadata']['dist']['allow-dirty']) == {'ci', 'msi'}, 'only reviewed CI/MSI generation overrides are allowed')
require(product.find("w:Binary[@Id='DepscanPathType']", ns).get('SourceFile') == '$(var.CargoTargetDir)\\msi-helper\\depscan-msi-path.dll', 'helper must be independent of cargo-dist executable staging')
require(product.find("w:CustomAction[@Id='DepscanTestFailure']", ns) is None, 'test failure injection cannot ship')
print('MSI source identity, version injection, generation overrides and helper contract verified')
