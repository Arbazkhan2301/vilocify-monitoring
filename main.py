import io
import os
import json
import logging
from datetime import datetime, timedelta, UTC

from cyclonedx.model.bom import Bom
from cyclonedx.model.bom import Component as BomComponent

from vilocify import api_config
from vilocify.models import MonitoringList, Component, Notification, Vulnerability
from vilocify.match import match_bom_component
from vilocify.models import MonitoringList
from vilocify.match import MissingPurlError

# -------------------------
# Configure your API token here
# -------------------------
api_config.token = "TuWDfThoCwg5tJJJibENFKtsYEn7afa2ArT73WeFCL89Z4VjefJQPFaeUT9pGocb"
COST_PER_REQUEST = 0.01  # Example cost per API request in EUR
api_request_counter = 0

def count_and_call(method):
    def wrapper(*args, **kwargs):
        global api_request_counter
        api_request_counter += 1
        # print(f"API Request #{api_request_counter}: {method.__name__}")
        return method(*args, **kwargs)
    return wrapper

api_methods = [
    "where",
    "first",
    "create",
    "update",
    "all",
]

for cls in [MonitoringList, Component, Notification, Vulnerability]:
    for method_name in api_methods:
        if hasattr(cls, method_name):
            original_method = getattr(cls, method_name)
            wrapped_method = count_and_call(original_method)
            setattr(cls, method_name, wrapped_method)

# -------------------------
# Logging Setup
# -------------------------
logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)


# -------------------------
# Helper to load BOM from file (json or xml)
# -------------------------
def load_bom(file_path: str) -> Bom:
    with open(file_path, "r", encoding="utf-8") as f:
        if file_path.endswith(".json"):
            bom = Bom.from_json(data=json.load(f))
        elif file_path.endswith(".xml"):
            bom = Bom.from_xml(data=f)
        else:
            raise ValueError("SBOM file must end with .json or .xml")
    return bom


# -------------------------
# Match BOM components to Vilocify components
# -------------------------
def find_vilocify_components(bom: Bom):
    matched_components = []
    number_of_matched = 0
    unmatched_components = []
    number_of_unmatched = 0
    
    for bom_comp in bom.components:
        try:
            vilocify_name, vilocify_version = match_bom_component(bom_comp)
        except MissingPurlError:
            logger.warning(f"Ignoring BOM component {bom_comp.name} due to missing PURL")
            unmatched_components.append(bom_comp)
            continue

        if vilocify_name is None or vilocify_version is None:
            logger.warning(f"Could not match BOM component {bom_comp.name} (purl: {bom_comp.purl})")
            unmatched_components.append(bom_comp)
            continue

        component = (
            Component.where("name", "eq", vilocify_name)
            .where("version", "eq", vilocify_version)
            .where("active", "eq", "true")
            .first()
        )

        if component:
            logger.info(f"Matched component {component.name} {component.version} (ID: {component.id})")
            matched_components.append(component)
            number_of_matched += 1
        else:
            logger.info(f"No Vilocify component found for {vilocify_name} {vilocify_version}")
            unmatched_components.append(bom_comp)
            number_of_unmatched += 1

    return matched_components, unmatched_components



# -------------------------
# Get or create monitoring list
# -------------------------
def get_or_create_monitoring_list(name: str, comment: str) -> MonitoringList:
    ml = MonitoringList.where("name", "eq", name).where("comment", "eq", comment).first()
    if ml is None:
        ml = MonitoringList(name=name, comment=comment)
        ml.create()
        print("\n")
        logger.info(f"Created new monitoring list: ID = {ml.id}")
    else:
        print("\n")
        logger.info(f"Using existing monitoring list: ID = {ml.id}")
    return ml


# -------------------------
# Update monitoring list components
# -------------------------
def update_monitoring_list(ml: MonitoringList, components: list[Component]) -> None:
    ml.components = components
    ml.update()
    logger.info(f"Monitoring list updated with {len(components)} components.")


# -------------------------
# Fetch notifications since some days ago
# -------------------------
def fetch_notifications(ml_id: str) -> list[Notification]:
    notifications = (
        Notification.where("monitoringLists.id", "any", ml_id)
        .all()
    )
    return notifications


# -------------------------
# Print notifications with vulnerabilities
# -------------------------
def print_notifications(notifications: list[Notification]) -> None:
    if not notifications:
        print("\nNo notifications found.")
        return

    print(f"\nFound {len(notifications)} notifications:\n")

    for notification in notifications:
        print("Title:", notification.title)
        print("Description:\n", notification.description)
        print("Vulnerabilities:")

        # Safely get vulnerability IDs
        vuln_ids = list(notification.vulnerabilities.ids()) if notification.vulnerabilities else []

        if not vuln_ids:
            print("No vulnerabilities linked.")
            continue

        for vuln in Vulnerability.where("id", "in", vuln_ids):
            print(f"  CVE: {vuln.cve}")
            print(f"  CVSS: {vuln.cvss}")
            print(f"  Description: {vuln.description}")



# -------------------------
# Main
# -------------------------
def main(sbom_file_path: str):
    bom = load_bom(sbom_file_path)

    matched_components, unmatched_components = find_vilocify_components(bom)

    # Print matched components
    print(f"\nMatched Components: {len(matched_components)}")
    if matched_components:
        for c in matched_components:
            print(f"  - {c.name} {c.version} (ID: {c.id})")
    else:
        print("  None")

    # Print unmatched components from BOM
    print(f"\nUnmatched Components: {len(unmatched_components)}")
    if unmatched_components:
        for uc in unmatched_components:
            print(f"  - {uc.name} {uc.version} (PURL: {uc.purl})")
    else:
        print("  None")

    if not matched_components:
        logger.warning("No matched components found. Exiting.")
        return

    ml_name = f"Monitoring list for SBOM"
    ml_comment = "Auto-generated from SBOM import"
    ml = get_or_create_monitoring_list(ml_name, ml_comment)

    update_monitoring_list(ml, matched_components)

    notifications = fetch_notifications(ml.id)
    print_notifications(notifications)



if __name__ == "__main__":
    main("SBOMs/bom25.json")
    print(f"\nTotal API requests made: {api_request_counter}")
    print(f"Estimated weekly cost (@ {COST_PER_REQUEST} EUR/request): {api_request_counter * COST_PER_REQUEST:.2f} EUR")
    print(f"Estimated monthly cost (@ {COST_PER_REQUEST} EUR/request): {api_request_counter * COST_PER_REQUEST * 4:.2f} EUR")
    print(f"Estimated yearly cost (@ {COST_PER_REQUEST} EUR/request): {api_request_counter * COST_PER_REQUEST * 52:.2f} EUR")