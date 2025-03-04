"""Common utilities for the exploits."""

import ipaddress
import json
from typing import cast, Any
from urllib import parse

import tld
from ostorlab.agent.mixins import agent_report_vulnerability_mixin
from ostorlab.assets import domain_name as domain_asset
from ostorlab.assets import ipv4 as ipv4_asset
from ostorlab.assets import ipv6 as ipv6_asset
from ostorlab.assets import android_store as android_store_asset
from ostorlab.assets import ios_store as ios_store_asset
from ostorlab.agent.message import message as msg


def prepare_host(host: str) -> str:
    """Prepare the host for the request.
    Args:
        host: The host to prepare.
    Returns:
        The prepared host.
    """
    if _is_ipv6(host) is True:
        return f"[{host}]"
    return host


def _is_ipv4(potential_ip: str) -> bool:
    """check if the potential_ip is a valid ipv4.

    Args:
        potential_ip: string.

    Returns:
        - boolean.
    """
    ip, _ = _split_ipv4(potential_ip)
    try:
        ipaddress.IPv4Address(ip)
        return True
    except ValueError:
        return False


def _split_ipv4(potential_ip: str) -> tuple[str, str | None]:
    """split the potential_ip to get the ip and the port if existed.

    Args:
        potential_ip: string.

    Returns:
        - ip, port.
    """
    ip = potential_ip
    port = None
    if ":" in potential_ip:
        ip, port = potential_ip.split(":", maxsplit=1)
    return ip, port


def _is_ipv6(potential_ip: str) -> bool:
    """check if the potential_ip is a valid ipv6.

    Args:
        potential_ip: string.

    Returns:
        - boolean.
    """
    try:
        ipaddress.IPv6Address(potential_ip)
        return True
    except ValueError:
        return False


def build_vuln_location(
    message: msg.Message,
    target_url: str | None,
    file_path: str | None = None,
) -> agent_report_vulnerability_mixin.VulnerabilityLocation | None:
    """Build VulnerabilityLocation based on the asset.

    Args:
        message: The agent message.
        target_url: The URL
        file_path: The path of the file
    Returns:
        The vulnerability location object.
    """

    asset: (
        ipv4_asset.IPv4
        | ipv6_asset.IPv6
        | domain_asset.DomainName
        | android_store_asset.AndroidStore
        | ios_store_asset.IOSStore
        | None
    ) = None

    if "v3.asset.file" in message.selector:
        package_name = message.data.get("android_metadata", {}).get("package_name")
        bundle_id = message.data.get("ios_metadata", {}).get("bundle_id")
        if bundle_id is None and package_name is None:
            return None
        if bundle_id is not None:
            asset = ios_store_asset.IOSStore(bundle_id=bundle_id)
        if package_name is not None:
            asset = android_store_asset.AndroidStore(package_name=package_name)
        return agent_report_vulnerability_mixin.VulnerabilityLocation(
            asset=asset,
            metadata=[
                agent_report_vulnerability_mixin.VulnerabilityLocationMetadata(
                    metadata_type=agent_report_vulnerability_mixin.MetadataType.FILE_PATH,
                    value=file_path or "",
                )
            ],
        )
    else:
        if target_url is None:
            return None
        metadata = []
        target = parse.urlparse(target_url)
        ip = None
        port = None
        potential_ip = target_url
        if target.scheme != "":
            potential_ip = potential_ip.replace(f"{target.scheme}://", "")
        if _is_ipv4(potential_ip) is True:
            ip, port = _split_ipv4(potential_ip)
            asset = ipv4_asset.IPv4(host=ip, version=4, mask="32")
            metadata.append(
                agent_report_vulnerability_mixin.VulnerabilityLocationMetadata(
                    metadata_type=agent_report_vulnerability_mixin.MetadataType.URL,
                    value=f"https://{ip}",
                )
            )
        elif _is_ipv6(potential_ip) is True:
            asset = ipv6_asset.IPv6(host=potential_ip, version=6, mask="128")
            metadata.append(
                agent_report_vulnerability_mixin.VulnerabilityLocationMetadata(
                    metadata_type=agent_report_vulnerability_mixin.MetadataType.URL,
                    value=f"https://{potential_ip}",
                )
            )
        else:
            full_url = parse.urlunparse(
                (target.scheme, target.netloc, target.path, "", "", "")
            )
            metadata.append(
                agent_report_vulnerability_mixin.VulnerabilityLocationMetadata(
                    metadata_type=agent_report_vulnerability_mixin.MetadataType.URL,
                    value=full_url,
                )
            )
            asset = domain_asset.DomainName(name=prepare_domain_asset(target_url))

        if target.port is not None or (ip is not None and port is not None):
            metadata_type = agent_report_vulnerability_mixin.MetadataType.PORT
            metadata_value = str(target.port) if target.port is not None else port
            if metadata_value is not None:
                metadata.append(
                    agent_report_vulnerability_mixin.VulnerabilityLocationMetadata(
                        metadata_type=metadata_type, value=metadata_value
                    )
                )

        return agent_report_vulnerability_mixin.VulnerabilityLocation(
            asset=asset, metadata=metadata
        )


def prepare_domain_asset(url: str | None) -> str:
    """Prepares the domain asset object for the given URL.

    Args:
        url: The URL to extract the domain from.

    Returns:
        domain_asset.DomainName: A domain asset
    """
    if url is None:
        return ""

    canonized_domain = tld.get_tld(
        url, as_object=True, fix_protocol=True, fail_silently=True
    )

    if canonized_domain is None:
        return parse.urlparse(url).netloc

    tld_domain = cast(tld.Result, canonized_domain)
    result_neloc = tld_domain.parsed_url.netloc
    if ":" in result_neloc:
        asset = result_neloc.split(":")[0]
    else:
        asset = result_neloc

    return asset


def compute_dna(
    vuln_title: str,
    vuln_location: agent_report_vulnerability_mixin.VulnerabilityLocation | None,
    scans: dict[str, Any] | None = None,
) -> str:
    """Compute a deterministic, debuggable DNA representation for a vulnerability.

    Args:
        vuln_title: The title of the vulnerability.
        vuln_location: The location of the vulnerability.
        scans: The location of the vulnerability.

    Returns:
        A deterministic JSON representation of the vulnerability DNA.
    """
    dna_data: dict[str, Any] = {"title": vuln_title}

    if vuln_location is not None:
        location_dict: dict[str, Any] = vuln_location.to_dict()
        sorted_location_dict = sort_dict(location_dict)
        dna_data["location"] = sorted_location_dict

    if scans is not None:
        dna_data["scans"] = scans

    return json.dumps(dna_data, sort_keys=True)


def sort_dict(d: dict[str, Any] | list[Any]) -> dict[str, Any] | list[Any]:
    """Recursively sort dictionary keys and lists within.

    Args:
        d: The dictionary or list to sort.

    Returns:
        A sorted dictionary or list.
    """
    if isinstance(d, dict):
        return {k: sort_dict(v) for k, v in sorted(d.items())}
    if isinstance(d, list):
        return sorted(
            d,
            key=lambda x: json.dumps(x, sort_keys=True)
            if isinstance(x, dict)
            else str(x),
        )
    return d
