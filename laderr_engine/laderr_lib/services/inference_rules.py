import random
import string

from loguru import logger
from rdflib import Graph, URIRef, RDF, RDFS, Literal

from laderr_engine.laderr_lib.constants import LADERR_NS, VERBOSE
from laderr_engine.laderr_lib.services.graph import GraphHandler

class InferenceRules:
    """
    Implements inference rules for LaDeRR graphs.
    """

    @staticmethod
    def execute_rule_disabled_state(laderr_graph: Graph):
        """
        Enforces the rule: If a disposition (d1) disables another disposition (d2), then:
        - d1 is set to ENABLED.
        - d2 is set to DISABLED.
        - Any previous contradicting states are removed.

        :param laderr_graph: RDFLib graph containing LaDeRR data.
        :type laderr_graph: Graph
        """

        if (None, RDF.type, LADERR_NS.Disposition) not in laderr_graph:
            return

        new_triples = set()
        removed_triples = set()

        enabled = LADERR_NS.enabled
        disabled = LADERR_NS.disabled

        # Iterate over all entities that may disable others
        for d1 in laderr_graph.subjects(RDF.type, LADERR_NS.Disposition):
            for d2 in laderr_graph.objects(d1, LADERR_NS.disables):
                if (d2, RDF.type, LADERR_NS.Disposition) not in laderr_graph and \
                        (d2, RDF.type, LADERR_NS.Capability) not in laderr_graph and \
                        (d2, RDF.type, LADERR_NS.Vulnerability) not in laderr_graph:
                    continue  # Skip if d2 is not a relevant entity

                # Remove previous conflicting states
                removed_triples.add((d1, LADERR_NS.state, disabled))  # Remove old disabled state of d1
                removed_triples.add((d2, LADERR_NS.state, enabled))  # Remove old enabled state of d2

                # Set correct states
                if (d1, LADERR_NS.state, enabled) not in laderr_graph:
                    new_triples.add((d1, LADERR_NS.state, enabled))
                if (d2, LADERR_NS.state, disabled) not in laderr_graph:
                    new_triples.add((d2, LADERR_NS.state, disabled))

        # Apply removals first
        for triple in removed_triples:
            laderr_graph.remove(triple)
            VERBOSE and logger.info(f"Removed: {triple[0]} laderr:state {triple[2]}")

        # Apply new inferences
        for triple in new_triples:
            laderr_graph.add(triple)
            VERBOSE and logger.info(f"Inferred: {triple[0]} laderr:state {triple[2]}")

    @staticmethod
    def execute_rule_protects(laderr_graph: Graph):
        """
        Applies the 'protects' inference rule:
        If an entity with a capability disables a vulnerability of another entity,
        and the protects relationship does not already exist between them, infer that the second entity protects the first.
        """
        if (None, LADERR_NS.capabilities, None) not in laderr_graph or \
                (None, LADERR_NS.vulnerabilities, None) not in laderr_graph or \
                (None, LADERR_NS.disables, None) not in laderr_graph:
            return

        new_triples = set()

        for o1, d1 in laderr_graph.subject_objects(LADERR_NS.vulnerabilities):
            for o2, d2 in laderr_graph.subject_objects(LADERR_NS.capabilities):
                if (d2, LADERR_NS.disables, d1) in laderr_graph and (o2, LADERR_NS.protects, o1) not in laderr_graph:
                    new_triples.add((o2, LADERR_NS.protects, o1))

        for triple in new_triples:
            laderr_graph.add(triple)
            VERBOSE and logger.info(f"Inferred: {triple[0]} laderr:protects {triple[2]}")

    @staticmethod
    def execute_rule_inhibits(laderr_graph: Graph):
        """
        Applies the updated 'inhibits' inference rule:

        If there exist entities (o2, o3) such that:
        - o2 has capability c2, and o3 has capability c3
        - A vulnerability v1 exists
        - c2 disables v1
        - c3 exploits v1
        - o2 does not already inhibit o3

        Then infer: o2 inhibits o3.

        :param laderr_graph: RDFLib graph containing LaDeRR data.
        :type laderr_graph: Graph
        """
        new_triples = set()

        # Iterate over all entities that have capabilities
        for o2 in laderr_graph.subjects(RDF.type, LADERR_NS.Entity):
            for c2 in laderr_graph.objects(o2, LADERR_NS.capabilities):
                if (c2, RDF.type, LADERR_NS.Capability) not in laderr_graph:
                    continue

                # Find vulnerabilities that c2 disables
                for v1 in laderr_graph.objects(c2, LADERR_NS.disables):
                    if (v1, RDF.type, LADERR_NS.Vulnerability) not in laderr_graph:
                        continue

                    # Find entities (o3) that have capabilities (c3) exploiting v1
                    for o3 in laderr_graph.subjects(RDF.type, LADERR_NS.Entity):
                        if o2 == o3:
                            continue  # Avoid self-inhibition

                        for c3 in laderr_graph.objects(o3, LADERR_NS.capabilities):
                            if (c3, RDF.type, LADERR_NS.Capability) not in laderr_graph:
                                continue

                            if (c3, LADERR_NS.exploits, v1) in laderr_graph:
                                # Ensure inhibition is not already present
                                if (o2, LADERR_NS.inhibits, o3) not in laderr_graph:
                                    new_triples.add((o2, LADERR_NS.inhibits, o3))

        # Apply the inferred triples
        for triple in new_triples:
            laderr_graph.add(triple)
            VERBOSE and logger.info(f"Inferred: {triple[0]} laderr:inhibits {triple[2]}")

    @staticmethod
    def execute_rule_threatens(laderr_graph: Graph):
        """
        Applies the 'threatens' inference rule:
        If a capability exploits a vulnerability of another entity,
        and the threatens relationship does not already exist between them,
        infer that the second entity threatens the first.
        """
        if (None, LADERR_NS.capabilities, None) not in laderr_graph or \
                (None, LADERR_NS.vulnerabilities, None) not in laderr_graph or \
                (None, LADERR_NS.exploits, None) not in laderr_graph:
            return

        new_triples = set()

        for o1, d1 in laderr_graph.subject_objects(LADERR_NS.vulnerabilities):
            for o2, d2 in laderr_graph.subject_objects(LADERR_NS.capabilities):
                if (d2, LADERR_NS.exploits, d1) in laderr_graph and (o2, LADERR_NS.threatens, o1) not in laderr_graph:
                    new_triples.add((o2, LADERR_NS.threatens, o1))

        for triple in new_triples:
            laderr_graph.add(triple)
            VERBOSE and logger.info(f"Inferred: {triple[0]} laderr:threatens {triple[2]}")

    @staticmethod
    def execute_rule_resilience(laderr_graph):
        if (None, LADERR_NS.capabilities, None) not in laderr_graph or \
                (None, LADERR_NS.vulnerabilities, None) not in laderr_graph or \
                (None, LADERR_NS.disables, None) not in laderr_graph or \
                (None, LADERR_NS.exploits, None) not in laderr_graph or \
                (None, LADERR_NS.exposes, None) not in laderr_graph:
            return

        new_triples = set()

        enabled = LADERR_NS.enabled

        # Iterate over all combinations of entities and capabilities
        for o1, c1 in laderr_graph.subject_objects(LADERR_NS.capabilities):
            for o2, c2 in laderr_graph.subject_objects(LADERR_NS.capabilities):
                for o3, c3 in laderr_graph.subject_objects(LADERR_NS.capabilities):
                    for o1_vuln, v1 in laderr_graph.subject_objects(LADERR_NS.vulnerabilities):
                        # Check entities align
                        if o1 != o1_vuln:
                            continue

                        # Check capabilities belong to distinct entities
                        if o1 in {o2, o3}:
                            continue

                        # Capability c2 must have state ENABLED
                        if (c2, LADERR_NS.state, enabled) not in laderr_graph:
                            continue

                        # Check the required property relationships
                        if not ((c2, LADERR_NS.disables, v1) in laderr_graph and (
                                v1, LADERR_NS.exposes, c1) in laderr_graph and (
                                c3, LADERR_NS.exploits, v1) in laderr_graph):
                            continue

                        # Check if Resilience already exists
                        existing_resilience = None
                        for r in laderr_graph.subjects(RDF.type, LADERR_NS.Resilience):
                            if ((o1, LADERR_NS.resiliences, r) in laderr_graph and (
                                    r, LADERR_NS.preserves, c1) in laderr_graph and (
                                    r, LADERR_NS.preservesAgainst, c3) in laderr_graph and (
                                    r, LADERR_NS.preservesDespite, v1) in laderr_graph and (
                                    c2, LADERR_NS.sustains, r) in laderr_graph):
                                existing_resilience = r
                                break

                        if existing_resilience is None:
                            # Create new Resilience individual
                            resilience_id = "R" + ''.join(random.choices(string.ascii_uppercase + string.digits, k=2))
                            base_uri = GraphHandler.get_base_prefix(laderr_graph)
                            resilience_uri = URIRef(f"{base_uri}{resilience_id}")

                            # Add triples for new Resilience
                            new_triples.update({(resilience_uri, RDF.type, LADERR_NS.Resilience),
                                                (o1, LADERR_NS.resiliences, resilience_uri),
                                                (resilience_uri, LADERR_NS.preserves, c1),
                                                (resilience_uri, LADERR_NS.preservesAgainst, c3),
                                                (resilience_uri, LADERR_NS.preservesDespite, v1),
                                                (c2, LADERR_NS.sustains, resilience_uri),
                                                (resilience_uri, RDFS.label, Literal(resilience_id)),
                                                (resilience_uri, LADERR_NS.state, enabled)
                                                })

        for triple in new_triples:
            laderr_graph.add(triple)
            VERBOSE and logger.info(f"Inferred: {triple[0]} {triple[1]} {triple[2]}")

    @staticmethod
    def execute_rule_succeeded_to_damage(laderr_graph: Graph):
        """
        Applies the 'succeededToDamage' inference rule based on the updated definition:
        If two entities belong to the same LaderrSpecification, and an incident scenario applies,
        and one entity's capability exploits the other entity's vulnerability, exposing a capability,
        then the second entity succeeded to damage the first, and the scenario changes to NOT_RESILIENT.
        """
        # For each LaderrSpecification
        for ls in laderr_graph.subjects(RDF.type, LADERR_NS.LaderrSpecification):
            # Check if scenario(ls) = INCIDENT
            if (ls, LADERR_NS.scenario, LADERR_NS.incident) not in laderr_graph:
                continue

            # Get all entities composed in this specification
            entities = set(laderr_graph.objects(ls, LADERR_NS.composedOf))

            # Check all pairs of distinct entities (o1, o2)
            for o1 in entities:
                for o2 in entities:
                    if o1 == o2:
                        continue  # Skip self-pairing

                    # Search for a valid c1, v1, c2 matching the logic
                    found_valid_combination = False

                    for c1 in laderr_graph.objects(o1, LADERR_NS.capabilities):
                        for v1 in laderr_graph.objects(o1, LADERR_NS.vulnerabilities):
                            for c2 in laderr_graph.objects(o2, LADERR_NS.capabilities):
                                if not (
                                        (c2, LADERR_NS.exploits, v1) in laderr_graph and
                                        (v1, LADERR_NS.exposes, c1) in laderr_graph and
                                        (v1, LADERR_NS.state, LADERR_NS.enabled) in laderr_graph and
                                        (c2, LADERR_NS.state, LADERR_NS.enabled) in laderr_graph
                                ):
                                    continue

                                # All conditions met — success to damage
                                found_valid_combination = True
                                break

                            if found_valid_combination:
                                break

                        if found_valid_combination:
                            break

                    if found_valid_combination:
                        # If succeededToDamage does not already exist, infer it
                        if (o2, LADERR_NS.succeededToDamage, o1) not in laderr_graph:
                            laderr_graph.add((o2, LADERR_NS.succeededToDamage, o1))
                            VERBOSE and logger.info(f"Inferred: {o2} laderr:succeededToDamage {o1}")

                        # Update scenario to NOT_RESILIENT (this is new)
                        laderr_graph.set((ls, LADERR_NS.scenario, LADERR_NS.not_resilient))
                        VERBOSE and logger.info(f"Updated scenario of {ls} to NOT_RESILIENT")

    @staticmethod
    def execute_rule_failed_to_damage(laderr_graph: Graph):
        """
        Applies the 'failedToDamage' inference rule:
        If an entity (o2) has a capability that exploits a vulnerability of another entity (o1),
        and that vulnerability exposes a capability of o1, and the vulnerability is DISABLED,
        while the exploiting capability is ENABLED, and the failedToDamage relationship does not already exist
        between them, then o2 failed to damage o1.

        :param laderr_graph: RDFLib graph containing LaDeRR data.
        :type laderr_graph: Graph
        """
        new_triples = set()

        enabled = LADERR_NS.enabled
        disabled = LADERR_NS.disabled

        # Iterate over all entities and their capabilities and vulnerabilities
        for o1, c1 in laderr_graph.subject_objects(LADERR_NS.capabilities):
            for o1_vuln, v1 in laderr_graph.subject_objects(LADERR_NS.vulnerabilities):
                if o1 != o1_vuln:
                    continue

                for o2, c2 in laderr_graph.subject_objects(LADERR_NS.capabilities):
                    # Check if capability c2 exploits vulnerability v1
                    if (c2, LADERR_NS.exploits, v1) not in laderr_graph:
                        continue

                    # Check if vulnerability v1 exposes capability c1
                    if (v1, LADERR_NS.exposes, c1) not in laderr_graph:
                        continue

                    # Vulnerability must be DISABLED, and the exploiting capability must be ENABLED
                    if (v1, LADERR_NS.state, disabled) not in laderr_graph or (
                            c2, LADERR_NS.state, enabled) not in laderr_graph:
                        continue

                    # Only add failedToDamage if not already present
                    if (o2, LADERR_NS.failedToDamage, o1) not in laderr_graph:
                        new_triples.add((o2, LADERR_NS.failedToDamage, o1))

        for triple in new_triples:
            laderr_graph.add(triple)
            VERBOSE and logger.info(f"Inferred: {triple[0]} laderr:failedToDamage {triple[2]}")

    @staticmethod
    def execute_rule_scenario_resilient(laderr_graph: Graph):
        """
        Applies the 'scenario = RESILIENT' inference rule:
        If a LaDeRR Specification (ls) contains an entity (o) with a vulnerability (v) that is DISABLED,
        and the current scenario of the specification is INCIDENT,
        then the scenario of the specification is set to RESILIENT, replacing the previous scenario.

        This method ensures that the schema rule allowing only one scenario is respected:
        - The existing `scenario` relation to INCIDENT will be removed before adding the new relation to RESILIENT.

        :param laderr_graph: RDFLib graph containing LaDeRR data.
        :type laderr_graph: Graph
        """
        new_triples = set()
        removed_triples = set()

        disabled = LADERR_NS.disabled
        incident = LADERR_NS.incident
        resilient = LADERR_NS.resilient

        # For each LaderrSpecification
        for ls in laderr_graph.subjects(RDF.type, LADERR_NS.LaderrSpecification):
            # Check if current scenario is INCIDENT
            if (ls, LADERR_NS.scenario, incident) not in laderr_graph:
                continue

            # Check all entities within this specification
            scenario_should_be_resilient = False
            for o in laderr_graph.objects(ls, LADERR_NS.composedOf):
                # Check all vulnerabilities of this entity
                for v in laderr_graph.objects(o, LADERR_NS.vulnerabilities):
                    # If any vulnerability is DISABLED, condition is met
                    if (v, LADERR_NS.state, disabled) in laderr_graph:
                        scenario_should_be_resilient = True
                        break

                if scenario_should_be_resilient:
                    break

            if scenario_should_be_resilient:
                # Remove current (incident) scenario
                removed_triples.add((ls, LADERR_NS.scenario, incident))

                # Set new scenario to RESILIENT
                new_triples.add((ls, LADERR_NS.scenario, resilient))

        # Apply changes
        for triple in removed_triples:
            laderr_graph.remove(triple)
            VERBOSE and logger.info(f"Removed: {triple[0]} laderr:scenario {triple[2]}")

        for triple in new_triples:
            laderr_graph.add(triple)
            VERBOSE and logger.info(f"Inferred: {triple[0]} laderr:scenario {triple[2]}")
