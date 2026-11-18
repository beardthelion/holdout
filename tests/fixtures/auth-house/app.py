class _App:
    def post(self, *a, **k):
        def deco(fn):
            return fn
        return deco


app = _App()
