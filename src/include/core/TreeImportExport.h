#pragma once

#include <syscaller.h>
#include <injection/ProcessLister.h>
#include <core/Thunks.h>
#include <tinyxml2.h>

class TreeImportExport
{
public:

	TreeImportExport(const WCHAR * targetXmlFile);

	bool exportTreeList(const std::map<DWORD_PTR, ImportModuleThunk> & moduleList, const Process * process, DWORD_PTR addressOEP, DWORD_PTR addressIAT, DWORD sizeIAT) ;
	bool importTreeList(std::map<DWORD_PTR, ImportModuleThunk> & moduleList, DWORD_PTR * addressOEP, DWORD_PTR * addressIAT, DWORD * sizeIAT);

private:

	WCHAR xmlPath[MAX_PATH];

	char xmlStringBuffer[MAX_PATH];
	
	tinyxml2::XMLDocument xmlDoc;

	void setTargetInformation(tinyxml2::XMLElement* rootElement, const Process * process, DWORD_PTR addressOEP, DWORD_PTR addressIAT, DWORD sizeIAT);
	void addModuleListToRootElement(tinyxml2::XMLElement* rootElement, const std::map<DWORD_PTR, ImportModuleThunk> & moduleList);

	void parseAllElementModules(tinyxml2::XMLElement* targetElement, std::map<DWORD_PTR, ImportModuleThunk> & moduleList);
	void parseAllElementImports(tinyxml2::XMLElement* moduleElement, ImportModuleThunk * importModuleThunk);

	tinyxml2::XMLElement* getModuleXmlElement(const ImportModuleThunk * importModuleThunk);
	tinyxml2::XMLElement* getImportXmlElement(const ImportThunk * importThunk);

	bool saveXmlToFile(const tinyxml2::XMLDocument& doc, const WCHAR * xmlFilePath);
	bool readXmlFile(tinyxml2::XMLDocument& doc, const WCHAR * xmlFilePath);

	void ConvertBoolToString(const bool boolValue);
	void ConvertWordToString(const WORD dwValue);
	void ConvertDwordPtrToString(const DWORD_PTR dwValue);

	DWORD_PTR ConvertStringToDwordPtr(const char * strValue);
	WORD ConvertStringToWord(const char * strValue);
	bool ConvertStringToBool(const char * strValue);
};
