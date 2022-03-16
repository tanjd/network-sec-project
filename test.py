class delftstack:
    def __init__(self, *args):
        if len(args) > 3:
            self.ans = args[0]
        elif len(args) <= 3:
            self.ans = "Less than three"
            


s1 = delftstack(1, 2, 3, 4)
print(s1.ans)

s2 = delftstack(1, 2)
print(s2.ans)
