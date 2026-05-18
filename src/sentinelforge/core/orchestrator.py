"""LangGraph-based orchestrator — wires all agents into a cyclic defense workflow.

Workflow:
  Monitor -> Investigator -> Containment -> Guardian -> Responder -> Explainer
  ^                                                                        |
  |_______________________________ (loop) ________________________________|

The Guardian sits between Containment and Responder to vet every action.
"""

from __future__ import annotations

from typing import TypedDict

from langgraph.graph import END, StateGraph

from sentinelforge.agents.containment import ContainmentAgent
from sentinelforge.agents.explainer import ExplainerAgent
from sentinelforge.agents.guardian import GuardianAgent
from sentinelforge.agents.investigator import InvestigatorAgent
from sentinelforge.agents.monitor import MonitorAgent
from sentinelforge.agents.responder import ResponderAgent
from sentinelforge.core.config import Settings, get_settings
from sentinelforge.core.logging import get_logger
from sentinelforge.core.models import OrchestratorState

logger = get_logger("orchestrator")

MAX_ITERATIONS = 10


class GraphState(TypedDict):
    state: OrchestratorState


def build_workflow(
    settings: Settings | None = None,
    use_llm: bool = True,
) -> StateGraph:
    """Build and compile the LangGraph defense workflow."""
    cfg = settings or get_settings()

    monitor = MonitorAgent(settings=cfg)
    investigator = InvestigatorAgent(use_llm=use_llm, settings=cfg)
    containment = ContainmentAgent(settings=cfg)
    guardian = GuardianAgent(settings=cfg)
    responder = ResponderAgent(settings=cfg)
    explainer = ExplainerAgent(use_llm=use_llm, settings=cfg)

    async def monitor_node(data: GraphState) -> GraphState:
        data["state"] = await monitor.run(data["state"])
        return data

    async def investigator_node(data: GraphState) -> GraphState:
        data["state"] = await investigator.run(data["state"])
        return data

    async def containment_node(data: GraphState) -> GraphState:
        data["state"] = await containment.run(data["state"])
        return data

    async def guardian_node(data: GraphState) -> GraphState:
        data["state"] = await guardian.run(data["state"])
        return data

    async def responder_node(data: GraphState) -> GraphState:
        data["state"] = await responder.run(data["state"])
        return data

    async def explainer_node(data: GraphState) -> GraphState:
        data["state"] = await explainer.run(data["state"])
        return data

    def should_continue(data: GraphState) -> str:
        s = data["state"]
        if not s.should_continue:
            return "end"
        if s.error:
            return "end"
        if s.iteration >= MAX_ITERATIONS:
            logger.warning("max_iterations_reached")
            return "end"
        if not s.events:
            return "end"
        if s.iteration > 0 and s.new_events_this_iteration == 0:
            logger.info("no_new_events_stopping")
            return "end"
        s.iteration += 1
        return "continue"

    graph = StateGraph(GraphState)

    graph.add_node("monitor", monitor_node)
    graph.add_node("investigator", investigator_node)
    graph.add_node("containment", containment_node)
    graph.add_node("guardian", guardian_node)
    graph.add_node("responder", responder_node)
    graph.add_node("explainer", explainer_node)

    graph.set_entry_point("monitor")
    graph.add_edge("monitor", "investigator")
    graph.add_edge("investigator", "containment")
    graph.add_edge("containment", "guardian")
    graph.add_edge("guardian", "responder")
    graph.add_edge("responder", "explainer")

    graph.add_conditional_edges(
        "explainer",
        should_continue,
        {"continue": "monitor", "end": END},
    )

    return graph


async def run_defense_cycle(
    settings: Settings | None = None,
    initial_state: OrchestratorState | None = None,
    use_llm: bool = True,
) -> OrchestratorState:
    """Run a single defense cycle through the full agent pipeline."""
    graph = build_workflow(settings=settings, use_llm=use_llm)
    compiled = graph.compile()

    state = initial_state or OrchestratorState()
    data: GraphState = {"state": state}

    logger.info("defense_cycle_start")
    result = await compiled.ainvoke(data)
    logger.info(
        "defense_cycle_complete",
        events=len(result["state"].events),
        investigations=len(result["state"].investigations),
        actions_executed=len(result["state"].executed_actions),
        reports=len(result["state"].reports),
        violations=len(result["state"].safety_violations),
    )

    return result["state"]
