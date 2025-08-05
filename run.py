import uvicorn
#from app.utils import get_urlhaus_iocs, test_csv_parsing,debug_csv_structure

if __name__ == "__main__":
    #get_urlhaus_iocs()
    #get_urlhaus_iocs_fixed()
    #debug_csv_structure()
    #test_csv_parsing()
    
    uvicorn.run("app.main:app", host="127.0.0.1", port=8080, reload=True)
