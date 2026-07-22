class ChainOfThoughtPattern:
    name = 'chain_of_thought'
    async def execute(self, agents, context):
        return {'pattern':self.name,'agents':[a.name for a in agents],'status':'stub'}
