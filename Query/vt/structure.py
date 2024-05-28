from dataclasses import dataclass


@dataclass(slots=True)
class Binary:
    """Binary structure"""
    pdf_info: dict = None
    magic: str = None
    tlsh: str = None
    last_analysis_date: str = None
    meaningful_name: list = None
    sigma_analysis_stats: list = None
    bundle_info: dict = None
    signature_info: dict = None
    packers: list = None
    crowdsourced_ids_results: dict = None
    crowdsourced_ids_stats: dict = None
    crowdsourced_yara_results: dict = None
    first_submission_date: str = None
    last_submission_date: str = None
    popular_threat_classification: dict = None
    tags: list = None
    ssdeep: str = None
    vhash: str = None
    creation_date: str = None
    sigma_analysis_summary: list = None
    sigma_analysis_results: list = None
    unique_sources: int = None
    authentihash: str = None
    total_votes: int = None
    last_modification_date: str = None
    type_tags: list = None
    type_extension: str = None
    type_description: str = None
    type_tag: str = None
    pe_info: dict = None
    times_submitted: int = None
    trid: list = None
    reputation: int = None
    sha1: str = None
    md5: str = None
    sha256: str = None
    size: int = None
    last_analysis_stats: dict = None
    last_analysis_results: dict = None
    sandbox_verdicts: dict = None
    detectiteasy: dict = None
    names: list = None
    trusted_verdict: dict = None
    known_distributors: list = None
    first_seen_itw_date: str = None
    nsrl_info: dict = None


@dataclass(slots=True)
class Domain:
    """Domain structure"""
    categories: dict = None
    last_https_certificate: dict = None
    total_votes: dict = None
    tags: list = None
    last_modification_date: int = None
    creation_date: int = None
    last_analysis_results: dict = None
    last_dns_records_date: int = None
    reputation: int = None
    last_https_certificate_date: int = None
    last_analysis_date: int = None
    tld: str = None
    registrar: str = None
    popularity_ranks: dict = None
    last_analysis_stats: dict = None
    whois_date: int = None
    whois: str = None
    jarm: str = None  # TODO : voir ce qu'on peut faire avec pour pivoter -> pcap/autre API
    last_dns_records: str = None
    last_update_date: int = None


@dataclass(slots=True)
class Ip:
    """IP structure"""
    last_analysis_results: dict = None
    total_votes: dict = None
    network: str = None
    regional_internet_registry: str = None
    continent: str = None
    last_analysis_stats: dict = None
    crowdsourced_context: list = None
    tags: list = None
    whois_date: int = None
    last_modification_date: int = None
    as_owner: str = None
    last_analysis_date: int = None
    reputation: int = None
    whois: str = None
    jarm: str = None
    last_https_certificate_date: int = None
    country: str = None
    last_https_certificate: dict = None
    asn: int = None
