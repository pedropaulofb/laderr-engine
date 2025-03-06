import random
import string

from loguru import logger
from rdflib import Graph, URIRef, RDF

from laderr_engine.laderr_lib.constants import LADERR_NS
from laderr_engine.laderr_lib.services.graph import GraphHandler

VERBOSE = True


class InferenceRules:
    """
    Implements inference rules for LaDeRR graphs.
    """

    @staticmethod
    def execute_rule_disabled_state(laderr_graph: Graph):
        """
        Applies the 'disabled state' inference rule:
        If a disposition (c1) has state ENABLED and disables another disposition (c2) that is also ENABLED,
        then c2's state is updated to DISABLED. This ensures the old state (ENABLED) is removed before adding DISABLED.

        :param laderr_graph: RDFLib graph containing LaDeRR data.
        :type laderr_graph: Graph
        """
        new_triples = set()
        removed_triples = set()

        enabled = LADERR_NS.enabled
        disabled = LADERR_NS.disabled

        # Iterate over all dispositions
        for c1 in laderr_graph.subjects(RDF.type, LADERR_NS.Disposition):
            if (c1, LADERR_NS.state, enabled) not in laderr_graph:
                continue

            # Check which dispositions are disabled by this enabled disposition
            for c2 in laderr_graph.objects(c1, LADERR_NS.disables):
                if (c2, RDF.type, LADERR_NS.Disposition) not in laderr_graph:
                    continue

                # Check if c2 is currently ENABLED (only then should it be set to DISABLED)
                if (c2, LADERR_NS.state, enabled) not in laderr_graph:
                    continue

                # Remove the current enabled state
                removed_triples.add((c2, LADERR_NS.state, enabled))

                # Infer that c2 must have state DISABLED
                new_triples.add((c2, LADERR_NS.state, disabled))

        # Apply removals first (removing 'enabled')
        for triple in removed_triples:
            laderr_graph.remove(triple)
            VERBOSE and logger.info(f"Removed: {triple[0]} laderr:state {triple[2]}")

        # Apply additions (setting 'disabled')
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
        Applies the 'inhibits' inference rule:
        If a capability disables another capability,
        and the inhibits relationship does not already exist between their respective entities,
        infer that the second entity inhibits the first entity.
        """
        new_triples = set()

        for o1, d1 in laderr_graph.subject_objects(LADERR_NS.capabilities):
            for o2, d2 in laderr_graph.subject_objects(LADERR_NS.capabilities):
                if (d2, LADERR_NS.disables, d1) in laderr_graph and (o2, LADERR_NS.inhibits, o1) not in laderr_graph:
                    new_triples.add((o2, LADERR_NS.inhibits, o1))

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
                                c1, LADERR_NS.exposedBy, v1) in laderr_graph and (
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
                                                (resilience_uri, LADERR_NS.state, enabled)
                                                # New requirement: resilience must also be ENABLED
                                                })

        for triple in new_triples:
            laderr_graph.add(triple)
            VERBOSE and logger.info(f"Inferred: {triple[0]} {triple[1]} {triple[2]}")

    @staticmethod
    def execute_rule_succeed_to_damage(laderr_graph: Graph):
        """
        Applies the 'succeededToDamage' inference rule:
        If an entity (o2) has a capability that exploits a vulnerability of another entity (o1),
        and that vulnerability exposes a capability of o1, and both the vulnerability and the exploiting capability
        are enabled, and the succeededToDamage relationship does not already exist between them,
        then o2 succeeded to damage o1.

        :param laderr_graph: RDFLib graph containing LaDeRR data.
        :type laderr_graph: Graph
        """
        new_triples = set()

        enabled = LADERR_NS.enabled

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

                    # Both the vulnerability and the exploiting capability must be enabled
                    if (v1, LADERR_NS.state, enabled) not in laderr_graph or (
                            c2, LADERR_NS.state, enabled) not in laderr_graph:
                        continue

                    # Only add succeededToDamage if not already present
                    if (o2, LADERR_NS.succeededToDamage, o1) not in laderr_graph:
                        new_triples.add((o2, LADERR_NS.succeededToDamage, o1))

        for triple in new_triples:
            laderr_graph.add(triple)
            VERBOSE and logger.info(f"Inferred: {triple[0]} laderr:succeededToDamage {triple[2]}")

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
    def execute_rule_scenario_not_resilient(laderr_graph: Graph):
        """
        Applies the 'scenario = NOT_RESILIENT' inference rule:
        If a LaDeRR Specification (ls) contains two entities (o1 and o2) where o1 succeeded to damage o2,
        and the current scenario of the specification is INCIDENT, then the scenario is changed to NOT_RESILIENT.

        This method ensures that the schema rule allowing only one scenario is respected:
        - The existing `scenario` relation to INCIDENT will be removed before adding the new relation to NOT_RESILIENT.

        :param laderr_graph: RDFLib graph containing LaDeRR data.
        :type laderr_graph: Graph
        """
        new_triples = set()
        removed_triples = set()

        incident = LADERR_NS.incident
        not_resilient = LADERR_NS.not_resilient

        # For each LaderrSpecification
        for ls in laderr_graph.subjects(RDF.type, LADERR_NS.LaderrSpecification):
            entities = set()

            # Collect all entities that are part of this specification
            for entity in laderr_graph.objects(ls, LADERR_NS.composedOf):
                entities.add(entity)

            # Check if current scenario is INCIDENT
            if (ls, LADERR_NS.scenario, incident) not in laderr_graph:
                continue  # Skip if not incident, because the rule does not apply

            # Check for any pair (o1, o2) within the same specification where o1 succeeded to damage o2
            for o1 in entities:
                for o2 in entities:
                    if (o1, LADERR_NS.succeededToDamage, o2) in laderr_graph:
                        # We need to remove the current (incident) scenario
                        removed_triples.add((ls, LADERR_NS.scenario, incident))

                        # Set the new scenario to NOT_RESILIENT
                        new_triples.add((ls, LADERR_NS.scenario, not_resilient))

                        # No need to keep checking once condition is satisfied for this spec
                        break
                else:
                    continue
                break

        # Apply changes to the graph
        for triple in removed_triples:
            laderr_graph.remove(triple)
            VERBOSE and logger.info(f"Removed: {triple[0]} laderr:scenario {triple[2]}")

        for triple in new_triples:
            laderr_graph.add(triple)
            VERBOSE and logger.info(f"Inferred: {triple[0]} laderr:scenario {triple[2]}")

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
