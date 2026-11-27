"""The memory graph's live activity frame: ids only, to owner sockets only."""

import json
from types import SimpleNamespace

import pytest
from member_memory_helpers import env as _member_env
from member_memory_helpers import request

from kiro_crew import memory_graph_activity as activity
from kiro_crew.dashboard.handlers import memory_member

env = _member_env


class _Socket:
    def __init__(self, closed: bool = False) -> None:
        self.closed = closed


class _Sockets:
    """An owner socket set and the frames ``broadcast_ws_owners`` was handed."""

    def __init__(self, *, open_sockets: int = 1) -> None:
        self.clients = {_Socket() for _ in range(open_sockets)}
        self.frames: list[tuple[str, dict]] = []

    def attach(self, state) -> None:
        state._owner_ws_clients = self.clients
        state.broadcast_ws_owners = lambda kind, data: self.frames.append((kind, data))


def test_a_frame_names_ids_kind_store_and_time_and_nothing_else():
    frame = activity.activity_frame(
        "member-alice", activity.RECALL, ["user.a", "", None, "user.a", "lesson.b"], now=12.5
    )
    assert frame == {
        "store": "member-alice",
        "kind": "recall",
        "ids": ["user.a", "lesson.b"],
        "ts": 12.5,
    }
    assert activity.activity_frame("", activity.SESSION_START, []) is None
    assert activity.activity_frame("default", activity.RECALL, ["user.a"])["store"] == ""
    with pytest.raises(ValueError):
        activity.activity_frame("", "search", ["user.a"])


def test_a_frame_is_capped():
    frame = activity.activity_frame("", activity.RECALL, [f"user.n{i}" for i in range(500)])
    assert frame is not None and len(frame["ids"]) == activity.IDS_CAP


def test_nothing_is_sent_without_an_open_owner_socket():
    state = SimpleNamespace()
    sockets = _Sockets(open_sockets=0)
    sockets.attach(state)
    state._owner_ws_clients = {_Socket(closed=True)}
    activity.announce(state, "", activity.RECALL, ["user.a"])
    assert sockets.frames == []
    # A state with no owner socket set at all is the same.
    activity.announce(SimpleNamespace(), "", activity.RECALL, ["user.a"])


def test_recalled_ids_take_lessons_facts_and_experiences_by_their_graph_ids():
    payload = {
        "retrieval": {
            "facts": [{"key": "user.a", "snippet": "x"}, {"id": "markdown:notes.md"}],
            "episodes": [{"id": "ep-1", "text": "y"}],
        }
    }
    assert activity.recalled_ids(payload, ["lesson.z"]) == ["lesson.z", "user.a", "ep-1"]
    assert activity.recalled_ids(None) == []


@pytest.mark.asyncio
@pytest.mark.parametrize("name", ["", "member-alice"])
async def test_a_recall_tells_the_owner_graph_which_memories_it_read_and_no_text(env, name):
    tier = env.tiers[name]
    secret = "PostgreSQL database decision PRIVATE_TEXT_SENTINEL"
    assert tier.write_episodic(secret, importance=1.0, defer_embedding=True)
    episode = tier.get_episodic_list()[0]["id"]
    sockets = _Sockets()
    sockets.attach(env.state)

    response = await memory_member.api_memory_recall(
        request(env, query={"q": "PostgreSQL database", "store": name or "default"}, owner=True)
    )

    assert response.status == 200
    assert [kind for kind, _ in sockets.frames] == [activity.FRAME]
    frame = sockets.frames[0][1]
    assert frame["kind"] == "recall" and frame["store"] == name
    assert episode in frame["ids"]
    # Ids, a kind, a store and a time: no memory text anywhere in the frame.
    assert set(frame) == {"store", "kind", "ids", "ts"}
    assert "PRIVATE_TEXT_SENTINEL" not in json.dumps(frame)


@pytest.mark.asyncio
async def test_a_recall_with_no_owner_dashboard_open_sends_nothing(env):
    tier = env.tiers[""]
    assert tier.write_episodic("PostgreSQL database decision", importance=1.0, defer_embedding=True)
    sockets = _Sockets(open_sockets=0)
    sockets.attach(env.state)

    response = await memory_member.api_memory_recall(
        request(env, query={"q": "PostgreSQL database", "store": "default"}, owner=True)
    )

    assert response.status == 200
    assert sockets.frames == []
