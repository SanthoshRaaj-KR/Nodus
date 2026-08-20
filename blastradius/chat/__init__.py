"""The chat agent: ask the graph questions in English.

Everything in here is layered so that the half worth trusting does not depend
on the half that talks to a model:

    tools.py     pure functions over HydraDB -> small dicts. No OpenAI import,
                 no API key, fully testable on their own.
    briefing.py  the situation pack injected into the prompt, cached against
                 the graph's read_epoch.
    agent.py     the only module that knows OpenAI exists.
    router.py    the FastAPI surface ui/server.py mounts.

The split is the point. A wrong answer from a supply-chain tool is worse than
no answer, so the facts are produced by code that can be unit-tested against a
real graph, and the model is left to choose between them and phrase the result.
"""
