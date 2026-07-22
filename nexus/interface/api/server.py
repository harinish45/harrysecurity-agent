from fastapi import FastAPI
app = FastAPI(title='NEXUS-STRIKE')

@app.get('/health')
def health():
    return {'status':'ok'}
