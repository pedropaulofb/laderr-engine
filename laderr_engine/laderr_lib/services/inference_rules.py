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

        for triple in removed_triples:
            if triple in laderr_graph:
                laderr_graph.remove(triple)
                VERBOSE and logger.info(f"Removed: {triple[0]} {triple[1]} {triple[2]}")

        for triple in new_triples:
            if triple not in laderr_graph:
                laderr_graph.add(triple)
                VERBOSE and logger.info(f"Inferred: {triple[0]} {triple[1]} {triple[2]}")

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
            if triple not in laderr_graph:
                laderr_graph.add(triple)
                VERBOSE and logger.info(f"Inferred: {triple[0]} {triple[1]} {triple[2]}")

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
            if triple not in laderr_graph:
                laderr_graph.add(triple)
                VERBOSE and logger.info(f"Inferred: {triple[0]} {triple[1]} {triple[2]}")

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
            if triple not in laderr_graph:
                laderr_graph.add(triple)
                VERBOSE and logger.info(f"Inferred: {triple[0]} {triple[1]} {triple[2]}")

    @staticmethod
    def execute_rule_resilience(laderr_graph: Graph):
        """
        Infers resilience when the following conditions hold:

        ∀ o1, c1, v1, o2, c2, o3, c3 (
            Entity(o1) ∧ Entity(o2) ∧ Entity(o3) ∧
            Capability(c1) ∧ Capability(c2) ∧ Capability(c3) ∧
            Vulnerability(v1) ∧
            capabilities(o1, c1) ∧ vulnerabilities(o1, v1) ∧
            capabilities(o2, c2) ∧ capabilities(o3, c3) ∧
            disables(c2, v1) ∧ exposes(v1, c1) ∧ exploits(c3, v1)
        ) → ∃! r (
            Resilience(r) ∧
            resiliences(o1, r) ∧ preserves(r, c1) ∧
            preservesAgainst(r, c3) ∧ preservesDespite(r, v1) ∧
            sustains(c2, r)
        )
        """

        if (None, RDF.type, LADERR_NS.Entity) not in laderr_graph:
            return  # Skip if no entities are defined

        enabled = LADERR_NS.enabled
        new_triples = set()

        for o1, c1 in laderr_graph.subject_objects(LADERR_NS.capabilities):
            for o1_vuln, v1 in laderr_graph.subject_objects(LADERR_NS.vulnerabilities):
                if o1 != o1_vuln:
                    continue  # Ensure vulnerability belongs to the same entity

                for o2, c2 in laderr_graph.subject_objects(LADERR_NS.capabilities):
                    for o3, c3 in laderr_graph.subject_objects(LADERR_NS.capabilities):

                        # Ensure capabilities belong to distinct entities
                        if o1 in {o2, o3}:
                            continue

                        # Ensure required relationships hold
                        if not ((c2, LADERR_NS.disables, v1) in laderr_graph and
                                (v1, LADERR_NS.exposes, c1) in laderr_graph and
                                (c3, LADERR_NS.exploits, v1) in laderr_graph):
                            continue

                        # Check if resilience already exists
                        existing_resilience = None
                        for r in laderr_graph.subjects(RDF.type, LADERR_NS.Resilience):
                            if ((o1, LADERR_NS.resiliences, r) in laderr_graph and
                                    (r, LADERR_NS.preserves, c1) in laderr_graph and
                                    (r, LADERR_NS.preservesAgainst, c3) in laderr_graph and
                                    (r, LADERR_NS.preservesDespite, v1) in laderr_graph and
                                    (c2, LADERR_NS.sustains, r) in laderr_graph):
                                existing_resilience = r
                                break

                        if existing_resilience is None:
                            # Create a unique Resilience instance
                            resilience_id = "R" + ''.join(random.choices(string.ascii_uppercase + string.digits, k=2))
                            base_uri = GraphHandler.get_base_prefix(laderr_graph)
                            resilience_uri = URIRef(f"{base_uri}{resilience_id}")

                            new_triples.update({
                                (resilience_uri, RDF.type, LADERR_NS.Resilience),
                                (o1, LADERR_NS.resiliences, resilience_uri),
                                (resilience_uri, LADERR_NS.preserves, c1),
                                (resilience_uri, LADERR_NS.preservesAgainst, c3),
                                (resilience_uri, LADERR_NS.preservesDespite, v1),
                                (c2, LADERR_NS.sustains, resilience_uri),
                                (resilience_uri, RDFS.label, Literal(resilience_id))
                            })

        # Apply inferred triples
        for triple in new_triples:
            if triple not in laderr_graph:
                laderr_graph.add(triple)
                VERBOSE and logger.info(f"Inferred: {triple[0]} {triple[1]} {triple[2]}")

    @staticmethod
    def execute_rule_resilience_scenario(laderr_graph: Graph):
        """
        Ensures that for every Resilience instance r, if all the elements related to r via
        laderr:preserves, laderr:preservesAgainst, and laderr:preservesDespite are found together
        as components of a Scenario s, then s must also include r as a laderr:components.

        Implements:
        ∀ r, c1, c2, v, s (
            Resilience(r) ∧ preserves(r, c1) ∧ preservesAgainst(r, c2) ∧ preservesDespite(r, v) ∧
            components(s, c1) ∧ components(s, c2) ∧ components(s, v)
            → components(s, r)
        )
        """
        from laderr_engine.laderr_lib.constants import LADERR_NS, VERBOSE

        for r in laderr_graph.subjects(RDF.type, LADERR_NS.Resilience):
            c1s = list(laderr_graph.objects(r, LADERR_NS.preserves))
            c2s = list(laderr_graph.objects(r, LADERR_NS.preservesAgainst))
            vs = list(laderr_graph.objects(r, LADERR_NS.preservesDespite))

            for c1 in c1s:
                for c2 in c2s:
                    for v in vs:
                        scenarios_with_all = (
                                set(laderr_graph.subjects(LADERR_NS.components, c1)) &
                                set(laderr_graph.subjects(LADERR_NS.components, c2)) &
                                set(laderr_graph.subjects(LADERR_NS.components, v))
                        )

                        for s in scenarios_with_all:
                            if (s, LADERR_NS.components, r) not in laderr_graph:
                                laderr_graph.add((s, LADERR_NS.components, r))
                                VERBOSE and logger.info(f"Inferred: {s} laderr:components {r}")

    @staticmethod
    def execute_rule_positive_damage(laderr_graph: Graph):
        """
        Applies the 'positiveDamage' inference rule based on the current definition:

        For each Scenario s and Entities o1, o2 that are components of s, if:
        - o1 has capability c1 and vulnerability v1,
        - o2 has capability c2,
        - c2 exploits v1,
        - v1 exposes c1,
        - v1 and c2 are enabled,
        - and positiveDamage(o2, o1) does not already exist,

        Then:
        - Assert positiveDamage(o2, o1),
        - Set status(s) := VULNERABLE (if not already).
        """
        new_triples = set()
        removed_triples = set()

        for scenario in laderr_graph.subjects(RDF.type, LADERR_NS.Scenario):
            scenario_status = laderr_graph.value(scenario, LADERR_NS.status)

            # Get all entities that are components of the scenario
            scenario_entities = {
                e for e in laderr_graph.objects(scenario, LADERR_NS.components)
                if (e, RDF.type, LADERR_NS.Entity) in laderr_graph
            }

            for o1 in scenario_entities:
                for o2 in scenario_entities:
                    if o1 == o2:
                        continue

                    if (o2, LADERR_NS.positiveDamage, o1) in laderr_graph:
                        continue  # Skip if already inferred

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

                                # Inference: positiveDamage(o2, o1)
                                new_triples.add((o2, LADERR_NS.positiveDamage, o1))
                                VERBOSE and logger.info(f"Inferred: {o2} laderr:positiveDamage {o1}")

                                # Inference: status(scenario) = VULNERABLE (if not already)
                                if scenario_status != LADERR_NS.vulnerable:
                                    if scenario_status:
                                        removed_triples.add((scenario, LADERR_NS.status, scenario_status))
                                        VERBOSE and logger.info(f"Removed previous status: {scenario_status}")
                                    new_triples.add((scenario, LADERR_NS.status, LADERR_NS.vulnerable))
                                    VERBOSE and logger.info(f"Inferred: {scenario} laderr:status laderr:vulnerable")

        # Apply all removals first
        for triple in removed_triples:
            laderr_graph.remove(triple)

        # Apply all inferences
        for triple in new_triples:
            laderr_graph.add(triple)

    @staticmethod
    def execute_rule_negative_damage(laderr_graph: Graph):
        """
        Applies the 'negativeDamage' inference rule.

        For all pairs of entities o1 and o2, if:
        - o1 has capability c1 and vulnerability v1,
        - o2 has capability c2,
        - c2 exploits v1,
        - v1 exposes c1,
        - v1 is DISABLED and c2 is ENABLED,
        - and negativeDamage(o2, o1) does not already exist,

        Then:
        - Assert negativeDamage(o2, o1)

        :param laderr_graph: RDFLib graph containing LaDeRR data.
        :type laderr_graph: Graph
        """
        new_triples = set()

        for o1 in laderr_graph.subjects(RDF.type, LADERR_NS.Entity):
            for o2 in laderr_graph.subjects(RDF.type, LADERR_NS.Entity):
                if o1 == o2:
                    continue

                # Skip if already inferred
                if (o2, LADERR_NS.negativeDamage, o1) in laderr_graph:
                    continue

                c1_list = list(laderr_graph.objects(o1, LADERR_NS.capabilities))
                v1_list = list(laderr_graph.objects(o1, LADERR_NS.vulnerabilities))
                c2_list = list(laderr_graph.objects(o2, LADERR_NS.capabilities))

                for c1 in c1_list:
                    for v1 in v1_list:
                        for c2 in c2_list:
                            if not (
                                    (c2, LADERR_NS.exploits, v1) in laderr_graph and
                                    (v1, LADERR_NS.exposes, c1) in laderr_graph and
                                    (v1, LADERR_NS.state, LADERR_NS.disabled) in laderr_graph and
                                    (c2, LADERR_NS.state, LADERR_NS.enabled) in laderr_graph
                            ):
                                continue

                            # All conditions satisfied — assert negativeDamage
                            new_triples.add((o2, LADERR_NS.negativeDamage, o1))
                            VERBOSE and logger.info(f"Inferred: {o2} laderr:negativeDamage {o1}")

        # Apply inferences
        for triple in new_triples:
            laderr_graph.add(triple)

    @staticmethod
    def execute_rule_scenario_status(laderr_graph: Graph):
        """
        A scenario is marked RESILIENT if all its vulnerabilities are either DISABLED or NOT exploited by any capability.
        If the scenario fails that condition, it is marked VULNERABLE (unless already marked).
        """
        for scenario in laderr_graph.subjects(RDF.type, LADERR_NS.Scenario):
            current_status = laderr_graph.value(scenario, LADERR_NS.status)

            is_resilient = True

            for o1 in laderr_graph.objects(scenario, LADERR_NS.components):
                for v1 in laderr_graph.objects(o1, LADERR_NS.vulnerabilities):
                    is_enabled = (v1, LADERR_NS.state, LADERR_NS.enabled) in laderr_graph

                    if is_enabled:
                        is_exploited = any(laderr_graph.subjects(LADERR_NS.exploits, v1))

                        if is_exploited:
                            is_resilient = False
                            break

                if not is_resilient:
                    break

            if is_resilient:
                if current_status != LADERR_NS.resilient:
                    if current_status:
                        laderr_graph.remove((scenario, LADERR_NS.status, current_status))
                        VERBOSE and logger.info(f"Removed previous status: {current_status} from {scenario}")
                    laderr_graph.add((scenario, LADERR_NS.status, LADERR_NS.resilient))
                    VERBOSE and logger.info(f"Inferred: {scenario} laderr:status laderr:resilient")
            else:
                if current_status != LADERR_NS.vulnerable:
                    if current_status:
                        laderr_graph.remove((scenario, LADERR_NS.status, current_status))
                        VERBOSE and logger.info(f"Removed previous status: {current_status} from {scenario}")
                    laderr_graph.add((scenario, LADERR_NS.status, LADERR_NS.vulnerable))
                    VERBOSE and logger.info(f"Inferred: {scenario} laderr:status laderr:vulnerable")

    @staticmethod
    def execute_rule_damage_from_scenario(laderr_graph: Graph):
        """
        Applies inference based on the scenario's situation (INCIDENT or OPERATIONAL):

        For each Scenario s:
        - If situation(s) = INCIDENT:
            - If positiveDamage(x, y) and not damaged(x, y), then damaged(x, y)
            - If negativeDamage(x, y) and not notDamaged(x, y), then notDamaged(x, y)

        - If situation(s) = OPERATIONAL:
            - If positiveDamage(x, y) and not canDamage(x, y), then canDamage(x, y)
            - If negativeDamage(x, y) and not cannotDamage(x, y), then cannotDamage(x, y)
        """
        new_triples = set()

        for scenario in laderr_graph.subjects(RDF.type, LADERR_NS.Scenario):
            situation = laderr_graph.value(scenario, LADERR_NS.situation)

            if situation == LADERR_NS.incident:
                # For INCIDENT: infer damaged / notDamaged
                for x, y in laderr_graph.subject_objects(LADERR_NS.positiveDamage):
                    if (x, LADERR_NS.damaged, y) not in laderr_graph:
                        new_triples.add((x, LADERR_NS.damaged, y))
                        VERBOSE and logger.info(f"Inferred (INCIDENT): {x} laderr:damaged {y}")
                for x, y in laderr_graph.subject_objects(LADERR_NS.negativeDamage):
                    if (x, LADERR_NS.notDamaged, y) not in laderr_graph:
                        new_triples.add((x, LADERR_NS.notDamaged, y))
                        VERBOSE and logger.info(f"Inferred (INCIDENT): {x} laderr:notDamaged {y}")

            elif situation == LADERR_NS.operational:
                # For OPERATIONAL: infer canDamage / cannotDamage
                for x, y in laderr_graph.subject_objects(LADERR_NS.positiveDamage):
                    if (x, LADERR_NS.canDamage, y) not in laderr_graph:
                        new_triples.add((x, LADERR_NS.canDamage, y))
                        VERBOSE and logger.info(f"Inferred (OPERATIONAL): {x} laderr:canDamage {y}")
                for x, y in laderr_graph.subject_objects(LADERR_NS.negativeDamage):
                    if (x, LADERR_NS.cannotDamage, y) not in laderr_graph:
                        new_triples.add((x, LADERR_NS.cannotDamage, y))
                        VERBOSE and logger.info(f"Inferred (OPERATIONAL): {x} laderr:cannotDamage {y}")

        # Add all inferred triples to the graph
        for triple in new_triples:
            laderr_graph.add(triple)
