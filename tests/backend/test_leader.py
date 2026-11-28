"""Leader election: single active writer, TTL takeover, fail-open."""

import asyncio

from elasticsearch import ConflictError

from backend.app.services.leader import LeaderElector


class FakeClient:
    """Minimal ES client modelling one lock doc with seq_no/primary_term CAS."""

    def __init__(self):
        self.docs = {}
        self.seq = 0

    async def get(self, index, id):
        key = (index, id)
        if key not in self.docs:
            from elasticsearch import NotFoundError

            raise NotFoundError("missing", None, None)
        source, seq, term = self.docs[key]
        return {"_source": source, "_seq_no": seq, "_primary_term": term}

    async def index(self, index, id, document, op_type=None, if_seq_no=None, if_primary_term=None, refresh=None):
        key = (index, id)
        if op_type == "create" and key in self.docs:
            raise ConflictError("exists", None, None)
        if if_seq_no is not None:
            _, seq, _ = self.docs[key]
            if seq != if_seq_no:
                raise ConflictError("stale", None, None)
        self.seq += 1
        self.docs[key] = (document, self.seq, 1)

    async def delete(self, index, id, if_seq_no=None, if_primary_term=None, refresh=None):
        self.docs.pop((index, id), None)


class StoreWithClient:
    def __init__(self):
        self.client = FakeClient()


class SimpleStore:
    pass


def test_simple_store_without_client_is_always_leader():
    elector = LeaderElector(SimpleStore())
    assert not elector.enabled
    assert asyncio.run(elector.is_leader()) is True


def test_only_one_of_two_contenders_wins_then_renews():
    store = StoreWithClient()
    a = LeaderElector(store, ttl_seconds=30)
    b = LeaderElector(store, ttl_seconds=30)

    async def scenario():
        first = await a.is_leader()
        second = await b.is_leader()
        # a created the lease; b sees a live lease it does not own.
        assert first is True and second is False
        # a renews its own lease repeatedly.
        assert await a.is_leader() is True
        return True

    assert asyncio.run(scenario())


def test_expired_lease_is_taken_over():
    store = StoreWithClient()
    holder = LeaderElector(store, ttl_seconds=0)  # lease expires immediately
    taker = LeaderElector(store, ttl_seconds=30)

    async def scenario():
        assert await holder.is_leader() is True
        # Lease from holder is already expired (ttl 0), so taker can seize it.
        assert await taker.is_leader() is True
        # Now holder no longer owns it and taker's lease is live.
        assert await holder.is_leader() is False
        return True

    assert asyncio.run(scenario())


def test_release_lets_a_contender_take_over_immediately():
    store = StoreWithClient()
    a = LeaderElector(store, ttl_seconds=300)
    b = LeaderElector(store, ttl_seconds=300)

    async def scenario():
        assert await a.is_leader() is True
        assert await b.is_leader() is False
        await a.release()
        assert await b.is_leader() is True
        return True

    assert asyncio.run(scenario())
