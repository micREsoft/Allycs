#include "app/MainGui.h"
#include "core/Architecture.h"
//#include "PluginLoader.h"
//#include "ConfigurationHolder.h"
#include "core/PeParser.h"
#include "plugins/DllInjectionPlugin.h"
#include "gui/DisassemblerGui.h"
#include "gui/PickApiGui.h"
//#include "AllycsApi.h"
#include "core/ImportRebuilder.h"
#include "utils/SystemInformation.h"
#include "app/Allycs.h"
#include "gui/AboutGui.h"
#include "gui/DonateGui.h"
#include "gui/OptionsGui.h"
#include "core/TreeImportExport.h"

extern CAppModule _Module; // o_O

const WCHAR MainGui::filterExe[]    = L"Executable (*.exe)\0*.exe\0All files\0*.*\0";
const WCHAR MainGui::filterDll[]    = L"Dynamic Link Library (*.dll)\0*.dll\0All files\0*.*\0";
const WCHAR MainGui::filterExeDll[] = L"Executable (*.exe)\0*.exe\0Dynamic Link Library (*.dll)\0*.dll\0All files\0*.*\0";
const WCHAR MainGui::filterTxt[]    = L"Text file (*.txt)\0*.txt\0All files\0*.*\0";
const WCHAR MainGui::filterXml[]    = L"XML file (*.xml)\0*.xml\0All files\0*.*\0";
const WCHAR MainGui::filterMem[]    = L"MEM file (*.mem)\0*.mem\0All files\0*.*\0";

MainGui::MainGui() : selectedProcess(0), isProcessSuspended(false), isDarkModeEnabled(false), importsHandling(TreeImports), TreeImportsSubclass(this, IDC_TREE_IMPORTS)
{
	/*
	Logger::getDebugLogFilePath();
	ConfigurationHolder::loadConfiguration();
	PluginLoader::findAllPlugins();
	AllycsApi::initialize();
	SystemInformation::getSystemInformation();

	if(ConfigurationHolder::getConfigObject(DEBUG_PRIVILEGE)->isTrue())
	{
		processLister.setDebugPrivileges();
	}
	

	ProcessAccessHelp::getProcessModules(GetCurrentProcessId(), ProcessAccessHelp::ownModuleList);
	*/

	hIcon.LoadIcon(IDI_ICON_ALLYCS);
	hMenuImports.LoadMenu(IDR_MENU_IMPORTS);
	hMenuLog.LoadMenu(IDR_MENU_LOG);
	accelerators.LoadAccelerators(IDR_ACCELERATOR_MAIN);

	hIconCheck.LoadIcon(IDI_ICON_CHECK, 16, 16);
	hIconWarning.LoadIcon(IDI_ICON_WARNING, 16, 16);
	hIconError.LoadIcon(IDI_ICON_ERROR, 16, 16);
}

BOOL MainGui::PreTranslateMessage(MSG* pMsg)
{
	if(accelerators.TranslateAccelerator(m_hWnd, pMsg))
	{
		return TRUE; // handled keyboard shortcuts
	}
	else if(IsDialogMessage(pMsg))
	{
		return TRUE; // handled dialog messages
	}

	return FALSE;
}

void MainGui::InitDllStartWithPreSelect( PGUI_DLL_PARAMETER guiParam )
{
	ComboProcessList.ResetContent();
	std::vector<Process>& processList = Allycs::processLister.getProcessListSnapshotNative();
	int newSel = -1;
	for (size_t i = 0; i < processList.size(); i++)
	{
		if (processList[i].PID == guiParam->dwProcessId)
			newSel = (int)i;
		swprintf_s(stringBuffer, L"%04d - %s - %s", processList[i].PID, processList[i].filename, processList[i].fullPath);
		ComboProcessList.AddString(stringBuffer);
	}
	if (newSel != -1)
	{
		ComboProcessList.SetCurSel(newSel);
		processSelectedActionHandler(newSel);

		if (guiParam->mod) //init mod
		{
			//select DLL
			size_t len = ProcessAccessHelp::moduleList.size();
			newSel = -1;
			for (size_t i = 0; i < len; i++)
			{
				if (ProcessAccessHelp::moduleList.at(i).modBaseAddr == (DWORD_PTR)guiParam->mod)
				{
					newSel = (int)i;
					break;
				}
			}
			if (newSel != -1)
			{
				//get selected module
				ProcessAccessHelp::selectedModule = &ProcessAccessHelp::moduleList.at(newSel);

				ProcessAccessHelp::targetImageBase = ProcessAccessHelp::selectedModule->modBaseAddr;
				ProcessAccessHelp::targetSizeOfImage = ProcessAccessHelp::selectedModule->modBaseSize;

				DWORD modEntryPoint = ProcessAccessHelp::getEntryPointFromFile(ProcessAccessHelp::selectedModule->fullPath);

				EditOEPAddress.SetValue(modEntryPoint + ProcessAccessHelp::targetImageBase);

				Allycs::windowLog.log(L"->>> Module %s selected.", ProcessAccessHelp::selectedModule->getFilename());
				Allycs::windowLog.log(L"Imagebase: " PRINTF_DWORD_PTR_FULL L" Size: %08X EntryPoint: %08X", ProcessAccessHelp::selectedModule->modBaseAddr, ProcessAccessHelp::selectedModule->modBaseSize, modEntryPoint);
			}
		}
	}
	if (guiParam->entrypoint)
		EditOEPAddress.SetValue(guiParam->entrypoint);
}

BOOL MainGui::OnInitDialog(CWindow wndFocus, LPARAM lInitParam)
{
	if (SystemInformation::currenOS == UNKNOWN_OS)
	{
		if(IDCANCEL == MessageBox(L"Operating System is not supported\r\nContinue anyway?", L"Allycs", MB_ICONWARNING | MB_OKCANCEL))
		{
			SendMessage(WM_CLOSE);
			return FALSE;
		}
	}

	// register ourselves to receive PreTranslateMessage
	CMessageLoop* pLoop = _Module.GetMessageLoop();
	pLoop->AddMessageFilter(this);

	setupStatusBar();

	DoDataExchange(); // attach controls
	DlgResize_Init(true, true); // init CDialogResize

	Allycs::windowLog.setWindow(ListLog);

	appendPluginListToMenu(hMenuImports.GetSubMenu(0));
	appendPluginListToMenu(CMenuHandle(GetMenu()).GetSubMenu(MenuImportsOffsetTrace));

	enableDialogControls(FALSE);
	setIconAndDialogCaption();

	// Load dark mode setting
	isDarkModeEnabled = Allycs::config[DARK_MODE].getBool();
	updateDarkModeButton();
	
	// Apply dark mode if enabled
	if (isDarkModeEnabled)
	{
		applyDarkMode(true);
	}

	if (lInitParam)
	{
		InitDllStartWithPreSelect((PGUI_DLL_PARAMETER)lInitParam);
	}
	return TRUE;
}


void MainGui::OnDestroy()
{
	PostQuitMessage(0);
}

void MainGui::OnSize(UINT nType, CSize size)
{
	StatusBar.SendMessage(WM_SIZE);
	SetMsgHandled(FALSE);
}

void MainGui::OnContextMenu(CWindow wnd, CPoint point)
{ 
	switch(wnd.GetDlgCtrlID())
	{
	case IDC_TREE_IMPORTS:
		DisplayContextMenuImports(wnd, point);
		return;
	case IDC_LIST_LOG:
		DisplayContextMenuLog(wnd, point);
		return;
	}

	SetMsgHandled(FALSE);
}

HBRUSH MainGui::OnCtlColorDlg(CDCHandle dc, CWindow wnd)
{
	if (isDarkModeEnabled)
	{
		static CBrush darkBrush = CreateSolidBrush(RGB(32, 32, 32));
		dc.SetTextColor(RGB(240, 240, 240));
		dc.SetBkColor(RGB(32, 32, 32));
		return darkBrush;
	}
	SetMsgHandled(FALSE);
	return NULL;
}

HBRUSH MainGui::OnCtlColorStatic(CDCHandle dc, CWindow wnd)
{
	if (isDarkModeEnabled)
	{
		static CBrush darkBrush = CreateSolidBrush(RGB(32, 32, 32));
		
		// Get the window class name to check if it's a group box
		WCHAR className[256] = {0};
		::GetClassName(wnd.m_hWnd, className, _countof(className));
		
		// Get the control ID to identify specific static controls
		int ctrlId = ::GetDlgCtrlID(wnd.m_hWnd);
		
		// Check if this is a group box (Button with BS_GROUPBOX style)
		if (wcscmp(className, L"Button") == 0)
		{
			LONG style = ::GetWindowLong(wnd.m_hWnd, GWL_STYLE);
			if ((style & BS_GROUPBOX) == BS_GROUPBOX)
			{
				// Use bright color for group box titles for better visibility
				// Using a bright cyan color for better contrast in dark mode
				dc.SetTextColor(RGB(255, 255, 255));
				// Important: Set the background mode to transparent for group box text
				dc.SetBkMode(TRANSPARENT);
				return darkBrush;
			}
		}
		
		// Make static text white for better visibility
		dc.SetTextColor(RGB(255, 255, 255));
		dc.SetBkColor(RGB(32, 32, 32));
		return darkBrush;
	}
	SetMsgHandled(FALSE);
	return NULL;
}

HBRUSH MainGui::OnCtlColorEdit(CDCHandle dc, CWindow wnd)
{
	if (isDarkModeEnabled)
	{
		static CBrush darkEditBrush = CreateSolidBrush(RGB(45, 45, 45));
		dc.SetTextColor(RGB(255, 255, 255));
		dc.SetBkColor(RGB(45, 45, 45));
		return darkEditBrush;
	}
	SetMsgHandled(FALSE);
	return NULL;
}

HBRUSH MainGui::OnCtlColorListBox(CDCHandle dc, CWindow wnd)
{
	if (isDarkModeEnabled)
	{
		static CBrush darkListBrush = CreateSolidBrush(RGB(45, 45, 45));
		dc.SetTextColor(RGB(255, 255, 255));
		dc.SetBkColor(RGB(45, 45, 45));
		
		// Check if this is a combo box dropdown
		HWND hwndParent = ::GetParent(wnd.m_hWnd);
		if (hwndParent != NULL)
		{
			WCHAR className[256] = {0};
			::GetClassName(hwndParent, className, _countof(className));
			if (wcscmp(className, L"ComboBox") == 0 || wcscmp(className, L"ComboLBox") == 0)
			{
				// Special handling for combo box dropdown
				dc.SetTextColor(RGB(255, 255, 255));
				dc.SetBkColor(RGB(45, 45, 45));
			}
		}
		
		return darkListBrush;
	}
	SetMsgHandled(FALSE);
	return NULL;
}

HBRUSH MainGui::OnCtlColorBtn(CDCHandle dc, CWindow wnd)
{
	if (isDarkModeEnabled)
	{
		// Use a slightly lighter background for buttons to create contrast
		static CBrush darkButtonBrush = CreateSolidBrush(RGB(60, 60, 60));
		
		// Make button text bright white for maximum visibility
		dc.SetTextColor(RGB(255, 255, 255));
		dc.SetBkColor(RGB(60, 60, 60));
		
		return darkButtonBrush;
	}
	SetMsgHandled(FALSE);
	return NULL;
}

HBRUSH MainGui::OnCtlColorScrollBar(CDCHandle dc, CWindow wnd)
{
	if (isDarkModeEnabled)
	{
		static CBrush darkScrollBrush = CreateSolidBrush(RGB(60, 60, 60));
		return darkScrollBrush;
	}
	SetMsgHandled(FALSE);
	return NULL;
}

void MainGui::OnCommand(UINT uNotifyCode, int nID, CWindow wndCtl)
{
	// Handle plugin trace menu selection
	if(uNotifyCode == 0 && !wndCtl.IsWindow()) // make sure it's a menu
	{
		if ((nID >= PLUGIN_MENU_BASE_ID) && (nID <= (int)(Allycs::plugins.getAllycsPluginList().size() + Allycs::plugins.getImprecPluginList().size() + PLUGIN_MENU_BASE_ID)))
		{
			pluginActionHandler(nID);
			return;
		}
	}
	SetMsgHandled(FALSE);
}

LRESULT MainGui::OnTreeImportsDoubleClick(const NMHDR* pnmh)
{
	if(TreeImports.GetCount() < 1)
		return 0;

	// Get item under cursor
	CTreeItem over = findTreeItem(CPoint(GetMessagePos()), true);
	if(over && importsHandling.isImport(over))
	{
		pickApiActionHandler(over);
	}

	return 0;
}

LRESULT MainGui::OnTreeImportsKeyDown(const NMHDR* pnmh)
{
	const NMTVKEYDOWN * tkd = (NMTVKEYDOWN *)pnmh;
	switch(tkd->wVKey)
	{
	case VK_RETURN:
		{
			CTreeItem selected = TreeImports.GetFocusItem();
			if(!selected.IsNull() && importsHandling.isImport(selected))
			{
				pickApiActionHandler(selected);
			}
		}
		return 1;
	case VK_DELETE:
		deleteSelectedImportsActionHandler();
		return 1;
	}

	SetMsgHandled(FALSE);
	return 0;
}

UINT MainGui::OnTreeImportsSubclassGetDlgCode(const MSG * lpMsg)
{
	if(lpMsg)
	{
		switch(lpMsg->wParam)
		{
		case VK_RETURN:
			return DLGC_WANTMESSAGE;
		}
	}

	SetMsgHandled(FALSE);
	return 0;
}

void MainGui::OnTreeImportsSubclassChar(UINT nChar, UINT nRepCnt, UINT nFlags)
{
	switch(nChar)
	{
		case VK_RETURN:
			break;
		default:
			SetMsgHandled(FALSE);
			break;
	}
}

void MainGui::OnProcessListDrop(UINT uNotifyCode, int nID, CWindow wndCtl)
{
	fillProcessListComboBox(ComboProcessList);
}

void MainGui::OnProcessListSelected(UINT uNotifyCode, int nID, CWindow wndCtl)
{
	int index = ComboProcessList.GetCurSel();
	if (index != CB_ERR)
	{
		processSelectedActionHandler(index);
	}
}

void MainGui::OnPickDLL(UINT uNotifyCode, int nID, CWindow wndCtl)
{
	pickDllActionHandler();
}

void MainGui::OnOptions(UINT uNotifyCode, int nID, CWindow wndCtl)
{
	optionsActionHandler();
}

void MainGui::OnDump(UINT uNotifyCode, int nID, CWindow wndCtl)
{
	dumpActionHandler();
}

void MainGui::OnDumpMemory(UINT uNotifyCode, int nID, CWindow wndCtl)
{
	dumpMemoryActionHandler();
}

void MainGui::OnDumpSection(UINT uNotifyCode, int nID, CWindow wndCtl)
{
	dumpSectionActionHandler();
}

void MainGui::OnFixDump(UINT uNotifyCode, int nID, CWindow wndCtl)
{
	dumpFixActionHandler();
}

void MainGui::OnPERebuild(UINT uNotifyCode, int nID, CWindow wndCtl)
{
	peRebuildActionHandler();
}

void MainGui::OnDLLInject(UINT uNotifyCode, int nID, CWindow wndCtl)
{
	dllInjectActionHandler();
}
void MainGui::OnDisassembler(UINT uNotifyCode, int nID, CWindow wndCtl)
{
	disassemblerActionHandler();
}

void MainGui::OnIATAutoSearch(UINT uNotifyCode, int nID, CWindow wndCtl)
{
	iatAutosearchActionHandler();
}

void MainGui::OnGetImports(UINT uNotifyCode, int nID, CWindow wndCtl)
{
	getImportsActionHandler();
}

void MainGui::OnInvalidImports(UINT uNotifyCode, int nID, CWindow wndCtl)
{
	showInvalidImportsActionHandler();
}

void MainGui::OnSuspectImports(UINT uNotifyCode, int nID, CWindow wndCtl)
{
	showSuspectImportsActionHandler();
}

void MainGui::OnClearImports(UINT uNotifyCode, int nID, CWindow wndCtl)
{
	clearImportsActionHandler();
}

void MainGui::OnInvalidateSelected(UINT uNotifyCode, int nID, CWindow wndCtl)
{
	invalidateSelectedImportsActionHandler();
}

void MainGui::OnCutSelected(UINT uNotifyCode, int nID, CWindow wndCtl)
{
	deleteSelectedImportsActionHandler();
}

void MainGui::OnSaveTree(UINT uNotifyCode, int nID, CWindow wndCtl)
{
	saveTreeActionHandler();
}

void MainGui::OnLoadTree(UINT uNotifyCode, int nID, CWindow wndCtl)
{
	loadTreeActionHandler();
}

void MainGui::OnAutotrace(UINT uNotifyCode, int nID, CWindow wndCtl)
{
	// TODO
}

void MainGui::OnExit(UINT uNotifyCode, int nID, CWindow wndCtl)
{
	if (isProcessSuspended)
	{
		int msgboxID = MessageBox(L"Process is suspended. Do you want to terminate the process?\r\n\r\nYES = Terminate Process\r\nNO = Try to resume the process\r\nCancel = Do nothing", L"Information", MB_YESNOCANCEL|MB_ICONINFORMATION);
		
		switch (msgboxID)
		{
		case IDYES:
			ProcessAccessHelp::terminateProcess();
			break;
		case IDNO:
			ProcessAccessHelp::resumeProcess();
			break;
		default:
			break;
		}
	}

	DestroyWindow();
}

void MainGui::OnAbout(UINT uNotifyCode, int nID, CWindow wndCtl)
{
	showAboutDialog();
}

void MainGui::OnDonate(UINT uNotifyCode, int nID, CWindow wndCtl)
{
	showDonateDialog();
}

void MainGui::OnDarkMode(UINT uNotifyCode, int nID, CWindow wndCtl)
{
	darkModeActionHandler();
}

void MainGui::setupStatusBar()
{
	StatusBar.Create(m_hWnd, NULL, L"", WS_CHILD | WS_VISIBLE | WS_CLIPCHILDREN | WS_CLIPSIBLINGS | SBARS_TOOLTIPS, NULL, IDC_STATUS_BAR);

	CRect rcMain, rcStatus;
	GetClientRect(&rcMain);
	StatusBar.GetWindowRect(&rcStatus);

	const int PARTS = 4;
	int widths[PARTS];

	widths[PART_COUNT]     = rcMain.Width() / 5;
	widths[PART_INVALID]   = widths[PART_COUNT] + rcMain.Width() / 5;
	widths[PART_IMAGEBASE] = widths[PART_INVALID] + rcMain.Width() / 3;
	widths[PART_MODULE]    = -1;

	StatusBar.SetParts(PARTS, widths);

	ResizeClient(rcMain.Width(), rcMain.Height() + rcStatus.Height(), FALSE);
}

void MainGui::updateStatusBar()
{
	// Rewrite ImportsHandling so we get these easily
	unsigned int totalImports = importsHandling.thunkCount();
	unsigned int invalidImports = importsHandling.invalidThunkCount();

	// \t = center, \t\t = right-align
	swprintf_s(stringBuffer, L"\tImports: %u", totalImports);
	StatusBar.SetText(PART_COUNT, stringBuffer);

	if(invalidImports > 0)
	{
		StatusBar.SetIcon(PART_INVALID, hIconError);
	}
	else
	{
		StatusBar.SetIcon(PART_INVALID, hIconCheck);
	}

	swprintf_s(stringBuffer, L"\tInvalid: %u", invalidImports);
	StatusBar.SetText(PART_INVALID, stringBuffer);

	if(selectedProcess)
	{
		DWORD_PTR imageBase = 0;
		const WCHAR * fileName = 0;

		if(ProcessAccessHelp::selectedModule)
		{
			imageBase = ProcessAccessHelp::selectedModule->modBaseAddr;
			fileName = ProcessAccessHelp::selectedModule->getFilename();
		}
		else
		{
			imageBase = selectedProcess->imageBase;
			fileName = selectedProcess->filename;
		}

		swprintf_s(stringBuffer, L"\tImagebase: " PRINTF_DWORD_PTR_FULL, imageBase);
		StatusBar.SetText(PART_IMAGEBASE, stringBuffer);
		StatusBar.SetText(PART_MODULE, fileName);
		StatusBar.SetTipText(PART_MODULE, fileName);
	}
	else
	{
		StatusBar.SetText(PART_IMAGEBASE, L"");
		StatusBar.SetText(PART_MODULE, L"");
	}
	
	// Apply dark mode to status bar if needed
	if (isDarkModeEnabled && StatusBar.IsWindow())
	{
		// Force redraw of status bar
		StatusBar.InvalidateRect(NULL, TRUE);
		StatusBar.UpdateWindow();
	}
}

bool MainGui::showFileDialog(WCHAR * selectedFile, bool save, const WCHAR * defFileName, const WCHAR * filter, const WCHAR * defExtension, const WCHAR * directory)
{
OPENFILENAME ofn = {0};

	// WTL doesn't support new explorer styles on Vista and up
	// This is because it uses a custom hook, we could remove it or derive
	// from CFileDialog but this solution is easier and allows more control anyway (e.g. initial dir)

	if(defFileName)
	{
		wcscpy_s(selectedFile, MAX_PATH, defFileName);
	}
	else
	{
		selectedFile[0] = L'\0';
	}

	ofn.lStructSize     = sizeof(ofn);
	ofn.hwndOwner       = m_hWnd;
	ofn.lpstrFilter     = filter;
	ofn.lpstrDefExt     = defExtension; // only first 3 chars are used, no dots!
	ofn.lpstrFile       = selectedFile;
	ofn.lpstrInitialDir = directory;
	ofn.nMaxFile        = MAX_PATH;
	ofn.Flags           = OFN_PATHMUSTEXIST | OFN_HIDEREADONLY;

	/*
	 *OFN_EXPLORER is automatically used, it only has to be specified
	 *if using a custom hook
	 *OFN_LONGNAMES is automatically used by explorer-style dialogs
	 */

	if(save)
		ofn.Flags |= OFN_OVERWRITEPROMPT;
	else
		ofn.Flags |= OFN_FILEMUSTEXIST;

	if(save)
		return 0 != GetSaveFileName(&ofn);
	else
		return 0 != GetOpenFileName(&ofn);
}

void MainGui::setIconAndDialogCaption()
{
	SetIcon(hIcon, TRUE);
	SetIcon(hIcon, FALSE);

	SetWindowText(APPNAME L" " ARCHITECTURE L" " APPVERSION);
}

void MainGui::pickDllActionHandler()
{
	if(!selectedProcess)
		return;

	PickDllGui dlgPickDll(ProcessAccessHelp::moduleList);
	if(dlgPickDll.DoModal())
	{
		//get selected module
		ProcessAccessHelp::selectedModule = dlgPickDll.getSelectedModule();

		ProcessAccessHelp::targetImageBase = ProcessAccessHelp::selectedModule->modBaseAddr;
		ProcessAccessHelp::targetSizeOfImage = ProcessAccessHelp::selectedModule->modBaseSize;

		DWORD modEntryPoint = ProcessAccessHelp::getEntryPointFromFile(ProcessAccessHelp::selectedModule->fullPath);

		EditOEPAddress.SetValue(modEntryPoint + ProcessAccessHelp::targetImageBase);

		Allycs::windowLog.log(L"->>> Module %s selected.", ProcessAccessHelp::selectedModule->getFilename());
		Allycs::windowLog.log(L"Imagebase: " PRINTF_DWORD_PTR_FULL L" Size: %08X EntryPoint: %08X", ProcessAccessHelp::selectedModule->modBaseAddr, ProcessAccessHelp::selectedModule->modBaseSize, modEntryPoint);
	}
	else
	{
		ProcessAccessHelp::selectedModule = 0;
	}

	updateStatusBar();
}

void MainGui::pickApiActionHandler(CTreeItem item)
{
	if(!importsHandling.isImport(item))
		return;

	// TODO: new node when user picked an API from another DLL?

	PickApiGui dlgPickApi(ProcessAccessHelp::moduleList);
	if(dlgPickApi.DoModal())
	{
		const ApiInfo* api = dlgPickApi.getSelectedApi();
		if(api && api->module)
		{
			importsHandling.setImport(item, api->module->getFilename(), api->name, api->ordinal, api->hint, true, api->isForwarded);
		}
	}

	updateStatusBar();
}

void MainGui::startDisassemblerGui(CTreeItem selectedTreeNode)
{
	if(!selectedProcess)
		return;

	DWORD_PTR address = importsHandling.getApiAddressByNode(selectedTreeNode);
	if (address)
	{
		BYTE test;
		if(!ProcessAccessHelp::readMemoryFromProcess(address, sizeof(test), &test))
		{
			swprintf_s(stringBuffer, L"Can't read memory at " PRINTF_DWORD_PTR_FULL, address);
			MessageBox(stringBuffer, L"Failure", MB_ICONERROR);
		}
		else
		{
			DisassemblerGui dlgDisassembler(address, &apiReader);
			dlgDisassembler.DoModal();
		}
	}
}

void MainGui::processSelectedActionHandler(int index)
{
	std::vector<Process>& processList = Allycs::processLister.getProcessList();
	Process &process = processList.at(index);
	selectedProcess = 0;

	clearImportsActionHandler();

	Allycs::windowLog.log(L"Analyzing %s", process.fullPath);

	if (ProcessAccessHelp::hProcess != 0)
	{
		ProcessAccessHelp::closeProcessHandle();
		apiReader.clearAll();
	}

	if (!ProcessAccessHelp::openProcessHandle(process.PID))
	{
		enableDialogControls(FALSE);
		Allycs::windowLog.log(L"Error: Cannot open process handle.");
		updateStatusBar();
		return;
	}

	ProcessAccessHelp::getProcessModules(ProcessAccessHelp::hProcess, ProcessAccessHelp::moduleList);

	apiReader.readApisFromModuleList();

	Allycs::windowLog.log(L"Loading modules done.");

	//TODO improve
	ProcessAccessHelp::selectedModule = 0;

	ProcessAccessHelp::targetImageBase = process.imageBase;
	ProcessAccessHelp::targetSizeOfImage = process.imageSize;

	process.imageSize = (DWORD)ProcessAccessHelp::targetSizeOfImage;


	Allycs::windowLog.log(L"Imagebase: " PRINTF_DWORD_PTR_FULL L" Size: %08X", process.imageBase, process.imageSize);

	process.entryPoint = ProcessAccessHelp::getEntryPointFromFile(process.fullPath);

	EditOEPAddress.SetValue(process.entryPoint + process.imageBase);

	selectedProcess = &process;
	enableDialogControls(TRUE);

	updateStatusBar();
}

void MainGui::fillProcessListComboBox(CComboBox& hCombo)
{
	hCombo.ResetContent();

	std::vector<Process>& processList = Allycs::processLister.getProcessListSnapshotNative();

	for (size_t i = 0; i < processList.size(); i++)
	{
		swprintf_s(stringBuffer, L"%04d - %s - %s", processList[i].PID, processList[i].filename, processList[i].fullPath);
		hCombo.AddString(stringBuffer);
	}
}

/*
void MainGui::addTextToOutputLog(const WCHAR * text)
{
	if (m_hWnd)
	{
		ListLog.SetCurSel(ListLog.AddString(text));
	}
}
*/

void MainGui::clearOutputLog()
{
	if (m_hWnd)
	{
		ListLog.ResetContent();
	}
}

bool MainGui::saveLogToFile(const WCHAR * file)
{
	const BYTE BOM[] = {0xFF, 0xFE}; // UTF-16 little-endian
	const WCHAR newLine[] = L"\r\n";
	bool success = true;

	HANDLE hFile = CreateFile(file, GENERIC_WRITE, FILE_SHARE_READ, 0, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
	if(hFile != INVALID_HANDLE_VALUE)
	{
		ProcessAccessHelp::writeMemoryToFileEnd(hFile, sizeof(BOM), BOM);

		WCHAR * buffer = 0;
		size_t bufsize = 0;
		for(int i = 0; i < ListLog.GetCount(); i++)
		{
			size_t size = ListLog.GetTextLen(i);
			size += _countof(newLine)-1;
			if(size+1 > bufsize)
			{
				bufsize = size+1;
				delete[] buffer;
				try
				{
					buffer = new WCHAR[bufsize];
				}
				catch(std::bad_alloc&)
				{
					buffer = 0;
					success = false;
					break;
				}
			}

			ListLog.GetText(i, buffer);
			wcscat_s(buffer, bufsize, newLine);

			ProcessAccessHelp::writeMemoryToFileEnd(hFile, (DWORD)(size * sizeof(WCHAR)), buffer);
		}
		delete[] buffer;
		SysClose(hFile);
	}
	return success;
}

void MainGui::showInvalidImportsActionHandler()
{
	importsHandling.selectImports(true, false);
	GotoDlgCtrl(TreeImports);
}

void MainGui::showSuspectImportsActionHandler()
{
	importsHandling.selectImports(false, true);
	GotoDlgCtrl(TreeImports);
}

void MainGui::deleteSelectedImportsActionHandler()
{
	CTreeItem selected = TreeImports.GetFirstSelectedItem();
	while(!selected.IsNull())
	{
		if(importsHandling.isModule(selected))
		{
			importsHandling.cutModule(selected);
		}
		else
		{
			importsHandling.cutImport(selected);
		}
		selected = TreeImports.GetNextSelectedItem(selected);
	}
	updateStatusBar();
}

void MainGui::invalidateSelectedImportsActionHandler()
{
	CTreeItem selected = TreeImports.GetFirstSelectedItem();
	while(!selected.IsNull())
	{
		if(importsHandling.isImport(selected))
		{
			importsHandling.invalidateImport(selected);
		}
		selected = TreeImports.GetNextSelectedItem(selected);
	}
	updateStatusBar();
}

void MainGui::loadTreeActionHandler()
{
	if(!selectedProcess)
		return;

	WCHAR selectedFilePath[MAX_PATH];
	getCurrentModulePath(stringBuffer, _countof(stringBuffer));
	if(showFileDialog(selectedFilePath, false, NULL, filterXml, NULL, stringBuffer))
	{
		TreeImportExport treeIO(selectedFilePath);
		DWORD_PTR addrOEP = 0;
		DWORD_PTR addrIAT = 0;
		DWORD sizeIAT = 0;

		if(!treeIO.importTreeList(importsHandling.moduleList, &addrOEP, &addrIAT, &sizeIAT))
		{
			Allycs::windowLog.log(L"Loading tree file failed %s", selectedFilePath);
			MessageBox(L"Loading tree file failed.", L"Failure", MB_ICONERROR);
		}
		else
		{
			EditOEPAddress.SetValue(addrOEP);
			EditIATAddress.SetValue(addrIAT);
			EditIATSize.SetValue(sizeIAT);

			importsHandling.displayAllImports();
			updateStatusBar();

			Allycs::windowLog.log(L"Loaded tree file %s", selectedFilePath);
			Allycs::windowLog.log(L"-> OEP: " PRINTF_DWORD_PTR_FULL, addrOEP);
			Allycs::windowLog.log(L"-> IAT: " PRINTF_DWORD_PTR_FULL L" Size: " PRINTF_DWORD_PTR, addrIAT, sizeIAT);
		}
	}
}

void MainGui::saveTreeActionHandler()
{
	if(!selectedProcess)
		return;

	WCHAR selectedFilePath[MAX_PATH];
	getCurrentModulePath(stringBuffer, _countof(stringBuffer));
	if(showFileDialog(selectedFilePath, true, NULL, filterXml, L"xml", stringBuffer))
	{
		TreeImportExport treeIO(selectedFilePath);
		DWORD_PTR addrOEP = EditOEPAddress.GetValue();
		DWORD_PTR addrIAT = EditIATAddress.GetValue();
		DWORD sizeIAT = EditIATSize.GetValue();

		if(!treeIO.exportTreeList(importsHandling.moduleList, selectedProcess, addrOEP, addrIAT, sizeIAT))
		{
			Allycs::windowLog.log(L"Saving tree file failed %s", selectedFilePath);
			MessageBox(L"Saving tree file failed.", L"Failure", MB_ICONERROR);
		}
		else
		{
			Allycs::windowLog.log(L"Saved tree file %s", selectedFilePath);
		}
	}
}

void MainGui::iatAutosearchActionHandler()
{
	DWORD_PTR searchAddress = 0;
	DWORD_PTR addressIAT = 0, addressIATAdv = 0;
	DWORD sizeIAT = 0, sizeIATAdv = 0;
	IATSearch iatSearch;

	if(!selectedProcess)
		return;

	if(EditOEPAddress.GetWindowTextLength() > 0)
	{
		searchAddress = EditOEPAddress.GetValue();
		if (searchAddress)
		{

			if (Allycs::config[USE_ADVANCED_IAT_SEARCH].isTrue())
			{
				if (iatSearch.searchImportAddressTableInProcess(searchAddress, &addressIATAdv, &sizeIATAdv, true))
				{
					Allycs::windowLog.log(L"IAT Search Adv: IAT VA " PRINTF_DWORD_PTR_FULL L" RVA " PRINTF_DWORD_PTR_FULL L" Size 0x%04X (%d)", addressIATAdv, addressIATAdv - ProcessAccessHelp::targetImageBase, sizeIATAdv, sizeIATAdv);
				}
				else
				{
					Allycs::windowLog.log(L"IAT Search Adv: IAT not found at OEP " PRINTF_DWORD_PTR_FULL L"!", searchAddress);
				}
			}


			if (iatSearch.searchImportAddressTableInProcess(searchAddress, &addressIAT, &sizeIAT, false))
			{
				Allycs::windowLog.log(L"IAT Search Nor: IAT VA " PRINTF_DWORD_PTR_FULL L" RVA " PRINTF_DWORD_PTR_FULL L" Size 0x%04X (%d)", addressIAT, addressIAT - ProcessAccessHelp::targetImageBase, sizeIAT, sizeIAT);
			}
			else
			{
				Allycs::windowLog.log(L"IAT Search Nor: IAT not found at OEP " PRINTF_DWORD_PTR_FULL L"!", searchAddress);
			}

			if (addressIAT != 0 && addressIATAdv == 0)
			{
				setDialogIATAddressAndSize(addressIAT, sizeIAT);
			}
			else if (addressIAT == 0 && addressIATAdv != 0)
			{
				setDialogIATAddressAndSize(addressIATAdv, sizeIATAdv);
			}
			else if (addressIAT != 0 && addressIATAdv != 0)
			{
				if (addressIATAdv != addressIAT || sizeIAT != sizeIATAdv)
				{
					int msgboxID = MessageBox(L"Result of advanced and normal search is different. Do you want to use the IAT Search Advanced result?", L"Information", MB_YESNO|MB_ICONINFORMATION);
					if (msgboxID == IDYES)
					{
						setDialogIATAddressAndSize(addressIATAdv, sizeIATAdv);
					}
					else
					{
						setDialogIATAddressAndSize(addressIAT, sizeIAT);
					}
				}
				else
				{
					setDialogIATAddressAndSize(addressIAT, sizeIAT);
				}
			}
			
		}
	}
}

void MainGui::getImportsActionHandler()
{
	if(!selectedProcess)
		return;

	DWORD_PTR addressIAT = EditIATAddress.GetValue();
	DWORD sizeIAT = EditIATSize.GetValue();

	if (addressIAT && sizeIAT)
	{
		apiReader.readAndParseIAT(addressIAT, sizeIAT, importsHandling.moduleList);
		importsHandling.scanAndFixModuleList();
		importsHandling.displayAllImports();

		updateStatusBar();

		if (Allycs::config[SCAN_DIRECT_IMPORTS].isTrue())
		{
			iatReferenceScan.ScanForDirectImports = true;
			iatReferenceScan.ScanForNormalImports = false;
			iatReferenceScan.apiReader = &apiReader;
			iatReferenceScan.startScan(ProcessAccessHelp::targetImageBase, (DWORD)ProcessAccessHelp::targetSizeOfImage, addressIAT, sizeIAT);

			Allycs::windowLog.log(L"DIRECT IMPORTS - Found %d possible direct imports with %d unique APIs!", iatReferenceScan.numberOfFoundDirectImports(), iatReferenceScan.numberOfFoundUniqueDirectImports());

			if (iatReferenceScan.numberOfFoundDirectImports() > 0)
			{
				if (iatReferenceScan.numberOfDirectImportApisNotInIat() > 0)
				{
					Allycs::windowLog.log(L"DIRECT IMPORTS - Found %d additional api addresses!", iatReferenceScan.numberOfDirectImportApisNotInIat());
					DWORD sizeIatNew = iatReferenceScan.addAdditionalApisToList();
					Allycs::windowLog.log(L"DIRECT IMPORTS - Old IAT size 0x%08X new IAT size 0x%08X!", sizeIAT, sizeIatNew);
					EditIATSize.SetValue(sizeIatNew);
					importsHandling.scanAndFixModuleList();
					importsHandling.displayAllImports();
				}

				iatReferenceScan.printDirectImportLog();

				if (Allycs::config[FIX_DIRECT_IMPORTS_NORMAL].isTrue() && (Allycs::config[FIX_DIRECT_IMPORTS_UNIVERSAL].isTrue() == false))
				{
					int msgboxID = MessageBox(L"Direct Imports found. I can patch only direct imports by JMP/CALL (use universal method if you don't like this) but where is the junk byte?\r\n\r\nYES = After Instruction\r\nNO = Before the Instruction\r\nCancel = Do nothing", L"Information", MB_YESNOCANCEL|MB_ICONINFORMATION);

					if (msgboxID != IDCANCEL)
					{
						bool isAfter;
						if (msgboxID == IDYES)
						{
							isAfter = true;
						}
						else
						{
							isAfter = false;
						}

						iatReferenceScan.patchDirectImportsMemory(isAfter);
						Allycs::windowLog.log(L"DIRECT IMPORTS - Patched! Please dump target.");
					}

				}
			}

		}


		if (isIATOutsidePeImage(addressIAT))
		{
			Allycs::windowLog.log(L"WARNING! IAT is not inside the PE image, requires rebasing!");
		}
	}
}

void MainGui::SetupImportsMenuItems(CTreeItem item)
{
	bool isItem, isImport = false;
	isItem = !item.IsNull();
	if(isItem)
	{
		isImport = importsHandling.isImport(item);
	}

	CMenuHandle hSub = hMenuImports.GetSubMenu(0);

	UINT itemOnly = isItem ? MF_ENABLED : MF_GRAYED;
	UINT importOnly = isImport ? MF_ENABLED : MF_GRAYED;

	hSub.EnableMenuItem(ID__INVALIDATE, itemOnly);
	hSub.EnableMenuItem(ID__DISASSEMBLE, importOnly);
	hSub.EnableMenuItem(ID__CUTTHUNK, importOnly);

	hSub.EnableMenuItem(ID__DELETETREENODE, itemOnly);
}

void MainGui::DisplayContextMenuImports(CWindow hwnd, CPoint pt)
{
	if(TreeImports.GetCount() < 1)
		return;

	CTreeItem over, parent;

	if(pt.x == -1 && pt.y == -1) // invoked by keyboard
	{
		CRect pos;
		over = TreeImports.GetFocusItem();
		if(over)
		{
			over.EnsureVisible();
			over.GetRect(&pos, TRUE);
			TreeImports.ClientToScreen(&pos);
		}
		else
		{
			TreeImports.GetWindowRect(&pos);
		}
		pt = pos.TopLeft();
	}
	else
	{
		// Get item under cursor
		over = findTreeItem(pt, true);
	}

	SetupImportsMenuItems(over);

	CMenuHandle hSub = hMenuImports.GetSubMenu(0);
	BOOL menuItem = hSub.TrackPopupMenu(TPM_LEFTALIGN | TPM_RIGHTBUTTON | TPM_RETURNCMD, pt.x, pt.y, hwnd);
	if (menuItem)
	{
		if ((menuItem >= PLUGIN_MENU_BASE_ID) && (menuItem <= (int)(Allycs::plugins.getAllycsPluginList().size() + Allycs::plugins.getImprecPluginList().size() + PLUGIN_MENU_BASE_ID)))
		{
			//wsprintf(stringBuffer, L"%d %s\n",menuItem,pluginList[menuItem - PLUGIN_MENU_BASE_ID].pluginName);
			//MessageBox(stringBuffer, L"plugin selection");

			pluginActionHandler(menuItem);
			return;
		}
		switch (menuItem)
		{
		case ID__INVALIDATE:
			if(importsHandling.isModule(over))
				importsHandling.invalidateModule(over);
			else
				importsHandling.invalidateImport(over);
			break;
		case ID__DISASSEMBLE:
			startDisassemblerGui(over);
			break;
		case ID__EXPANDALLNODES:
			importsHandling.expandAllTreeNodes();
			break;
		case ID__COLLAPSEALLNODES:
			importsHandling.collapseAllTreeNodes();
			break;
		case ID__CUTTHUNK:
			importsHandling.cutImport(over);
			break;
		case ID__DELETETREENODE:
			importsHandling.cutModule(importsHandling.isImport(over) ? over.GetParent() : over);
			break;
		}
	}

	updateStatusBar();
}

void MainGui::DisplayContextMenuLog(CWindow hwnd, CPoint pt)
{
	if(pt.x == -1 && pt.y == -1) // invoked by keyboard
	{
		CRect pos;
		ListLog.GetWindowRect(&pos);
		pt = pos.TopLeft();
	}

	CMenuHandle hSub = hMenuLog.GetSubMenu(0);
	BOOL menuItem = hSub.TrackPopupMenu(TPM_LEFTALIGN | TPM_RIGHTBUTTON | TPM_RETURNCMD, pt.x, pt.y, hwnd);
	if (menuItem)
	{
		switch (menuItem)
		{
		case ID__SAVE:
			WCHAR selectedFilePath[MAX_PATH];
			getCurrentModulePath(stringBuffer, _countof(stringBuffer));
			if(showFileDialog(selectedFilePath, true, NULL, filterTxt, L"txt", stringBuffer))
			{
				saveLogToFile(selectedFilePath);
			}
			break;
		case ID__CLEAR:
			clearOutputLog();
			break;
		}
	}
}

void MainGui::appendPluginListToMenu(CMenuHandle hMenu)
{
	std::vector<Plugin> &allycsPluginList = Allycs::plugins.getAllycsPluginList();
	std::vector<Plugin> &imprecPluginList = Allycs::plugins.getImprecPluginList();

	if (allycsPluginList.size() > 0)
	{
		CMenuHandle newMenu;
		newMenu.CreatePopupMenu();

		for (size_t i = 0; i < allycsPluginList.size(); i++)
		{
			newMenu.AppendMenu(MF_STRING, i + PLUGIN_MENU_BASE_ID, allycsPluginList[i].pluginName);
		}

		hMenu.AppendMenu(MF_MENUBARBREAK);
		hMenu.AppendMenu(MF_POPUP, newMenu, L"Allycs Plugins");
	}

	if (imprecPluginList.size() > 0)
	{
		CMenuHandle newMenu;
		newMenu.CreatePopupMenu();

		for (size_t i = 0; i < imprecPluginList.size(); i++)
		{
			newMenu.AppendMenu(MF_STRING, allycsPluginList.size() + i + PLUGIN_MENU_BASE_ID, imprecPluginList[i].pluginName);
		}

		hMenu.AppendMenu(MF_MENUBARBREAK);
		hMenu.AppendMenu(MF_POPUP, newMenu, L"ImpREC Plugins");
	}
}

void MainGui::dumpMemoryActionHandler()
{
	WCHAR selectedFilePath[MAX_PATH];
	DumpMemoryGui dlgDumpMemory;

	if(dlgDumpMemory.DoModal())
	{
		getCurrentModulePath(stringBuffer, _countof(stringBuffer));
		if(showFileDialog(selectedFilePath, true, dlgDumpMemory.dumpFilename, filterMem, L"mem", stringBuffer))
		{
			if (ProcessAccessHelp::writeMemoryToNewFile(selectedFilePath,dlgDumpMemory.dumpedMemorySize,dlgDumpMemory.dumpedMemory))
			{
				Allycs::windowLog.log(L"Memory dump saved %s", selectedFilePath);
			}
			else
			{
				Allycs::windowLog.log(L"Error! Cannot write memory dump to disk");
			}
		}
	}
}

void MainGui::dumpSectionActionHandler()
{
	WCHAR selectedFilePath[MAX_PATH] = {0};
    WCHAR defaultFilename[MAX_PATH] = {0};
	DumpSectionGui dlgDumpSection;
	const WCHAR * fileFilter;
	const WCHAR * defExtension;
	PeParser * peFile = 0;

	dlgDumpSection.entryPoint = EditOEPAddress.GetValue();

	if (ProcessAccessHelp::selectedModule)
	{
		//dump DLL
		fileFilter = filterDll;
		defExtension = L"dll";

		dlgDumpSection.imageBase = ProcessAccessHelp::selectedModule->modBaseAddr;
		//get it from gui
		wcscpy_s(dlgDumpSection.fullpath, ProcessAccessHelp::selectedModule->fullPath);
	}
	else
	{
		fileFilter = filterExe;
		defExtension = L"exe";

		dlgDumpSection.imageBase = ProcessAccessHelp::targetImageBase;
		//get it from gui
		wcscpy_s(dlgDumpSection.fullpath, selectedProcess->fullPath);
	}

	if(dlgDumpSection.DoModal())
	{
        getCurrentDefaultDumpFilename(defaultFilename, _countof(defaultFilename));
		getCurrentModulePath(stringBuffer, _countof(stringBuffer));
		if(showFileDialog(selectedFilePath, true, defaultFilename, fileFilter, defExtension, stringBuffer))
		{
			checkSuspendProcess();

			if (Allycs::config[USE_PE_HEADER_FROM_DISK].isTrue())
			{
				peFile = new PeParser(dlgDumpSection.fullpath, true);
			}
			else
			{
				peFile = new PeParser(dlgDumpSection.imageBase, true);
			}

			std::vector<PeSection> & sectionList = dlgDumpSection.getSectionList();

			if (peFile->dumpProcess(dlgDumpSection.imageBase, dlgDumpSection.entryPoint, selectedFilePath, sectionList))
			{
				Allycs::windowLog.log(L"Dump success %s", selectedFilePath);
			}
			else
			{
				Allycs::windowLog.log(L"Error: Cannot dump image.");
				MessageBox(L"Cannot dump image.", L"Failure", MB_ICONERROR);
			}

			delete peFile;
		}
	}
}

void MainGui::dumpActionHandler()
{
	if(!selectedProcess)
		return;

    WCHAR selectedFilePath[MAX_PATH] = {0};
    WCHAR defaultFilename[MAX_PATH] = {0};
	const WCHAR * fileFilter;
	const WCHAR * defExtension;
	DWORD_PTR modBase = 0;
	DWORD_PTR entrypoint = 0;
	WCHAR * filename = 0;
	PeParser * peFile = 0;

	if (ProcessAccessHelp::selectedModule)
	{
		fileFilter = filterDll;
		defExtension = L"dll";
	}
	else
	{
		fileFilter = filterExe;
		defExtension = L"exe";
	}

	getCurrentModulePath(stringBuffer, _countof(stringBuffer));
    getCurrentDefaultDumpFilename(defaultFilename, _countof(defaultFilename));
	if(showFileDialog(selectedFilePath, true, defaultFilename, fileFilter, defExtension, stringBuffer))
	{
		entrypoint = EditOEPAddress.GetValue();

		checkSuspendProcess();

		if (ProcessAccessHelp::selectedModule)
		{
			//dump DLL
			modBase = ProcessAccessHelp::selectedModule->modBaseAddr;
			filename = ProcessAccessHelp::selectedModule->fullPath;
		}
		else
		{
			//dump exe
			modBase = ProcessAccessHelp::targetImageBase;
			filename = selectedProcess->fullPath;
		}

		if (Allycs::config[USE_PE_HEADER_FROM_DISK].isTrue())
		{
			peFile = new PeParser(filename, true);
		}
		else
		{
			peFile = new PeParser(modBase, true);
		}

		if (peFile->isValidPeFile())
		{
			if (peFile->dumpProcess(modBase, entrypoint, selectedFilePath))
			{
				Allycs::windowLog.log(L"Dump success %s", selectedFilePath);
			}
			else
			{
				Allycs::windowLog.log(L"Error: Cannot dump image.");
				MessageBox(L"Cannot dump image.", L"Failure", MB_ICONERROR);
			}
		}
		else
		{
			Allycs::windowLog.log(L"Error: Invalid PE file or invalid PE header. Try reading PE header from disk/process.");
		}

		delete peFile;
	}
}

void MainGui::peRebuildActionHandler()
{
	DWORD newSize = 0;
	WCHAR selectedFilePath[MAX_PATH];

	getCurrentModulePath(stringBuffer, _countof(stringBuffer));
	if(showFileDialog(selectedFilePath, false, NULL, filterExeDll, NULL, stringBuffer))
	{
		if (Allycs::config[CREATE_BACKUP].isTrue())
		{
			if (!ProcessAccessHelp::createBackupFile(selectedFilePath))
			{
				Allycs::windowLog.log(L"Creating backup file failed %s", selectedFilePath);
			}
		}

		DWORD fileSize = (DWORD)ProcessAccessHelp::getFileSize(selectedFilePath);

		PeParser peFile(selectedFilePath, true);

		if (!peFile.isValidPeFile())
		{
			Allycs::windowLog.log(L"This is not a valid PE file %s", selectedFilePath);
			MessageBox(L"Not a valid PE file.", L"Failure", MB_ICONERROR);
			return;
		}

		if (peFile.readPeSectionsFromFile())
		{
			peFile.setDefaultFileAlignment();

			if (Allycs::config[REMOVE_DOS_HEADER_STUB].isTrue())
			{
				peFile.removeDosStub();
			}
			
			peFile.alignAllSectionHeaders();
			peFile.fixPeHeader();

			if (peFile.savePeFileToDisk(selectedFilePath))
			{
				newSize = (DWORD)ProcessAccessHelp::getFileSize(selectedFilePath);

				if (Allycs::config[UPDATE_HEADER_CHECKSUM].isTrue())
				{
					Allycs::windowLog.log(L"Generating PE header checksum");
					if (!PeParser::updatePeHeaderChecksum(selectedFilePath, newSize))
					{
						Allycs::windowLog.log(L"Generating PE header checksum FAILED!");
					}
				}

				Allycs::windowLog.log(L"Rebuild success %s", selectedFilePath);
				Allycs::windowLog.log(L"-> Old file size 0x%08X new file size 0x%08X (%d %%)", fileSize, newSize, ((newSize * 100) / fileSize) );
			}
			else
			{
				Allycs::windowLog.log(L"Rebuild failed, cannot save file %s", selectedFilePath);
				MessageBox(L"Rebuild failed. Cannot save file.", L"Failure", MB_ICONERROR);
			}
		}
		else
		{
			Allycs::windowLog.log(L"Rebuild failed, cannot read file %s", selectedFilePath);
			MessageBox(L"Rebuild failed. Cannot read file.", L"Failure", MB_ICONERROR);
		}

	}
}

void MainGui::dumpFixActionHandler()
{
	if(!selectedProcess)
		return;

	if (TreeImports.GetCount() < 2)
	{
		Allycs::windowLog.log(L"Nothing to rebuild");
		return;
	}

	WCHAR newFilePath[MAX_PATH];
	WCHAR selectedFilePath[MAX_PATH];
	const WCHAR * fileFilter;
	DWORD_PTR modBase = 0;
	DWORD_PTR entrypoint = EditOEPAddress.GetValue();

	if (ProcessAccessHelp::selectedModule)
	{
		modBase = ProcessAccessHelp::selectedModule->modBaseAddr;
		fileFilter = filterDll;
	}
	else
	{
		modBase = ProcessAccessHelp::targetImageBase;
		fileFilter = filterExe;
	}

	getCurrentModulePath(stringBuffer, _countof(stringBuffer));
	if (showFileDialog(selectedFilePath, false, NULL, fileFilter, NULL, stringBuffer))
	{
		wcscpy_s(newFilePath, selectedFilePath);

		const WCHAR * extension = 0;

		WCHAR* dot = wcsrchr(newFilePath, L'.');
		if (dot)
		{
			*dot = L'\0';
			extension = selectedFilePath + (dot - newFilePath); //wcsrchr(selectedFilePath, L'.');
		}

		wcscat_s(newFilePath, L"_SCY");

		if(extension)
		{
			wcscat_s(newFilePath, extension);
		}

		ImportRebuilder importRebuild(selectedFilePath);

		if (Allycs::config[IAT_FIX_AND_OEP_FIX].isTrue())
		{
			importRebuild.setEntryPointRva((DWORD)(entrypoint - modBase));
		}

		if (Allycs::config[OriginalFirstThunk_SUPPORT].isTrue())
		{
			importRebuild.enableOFTSupport();
		}

		if (Allycs::config[SCAN_DIRECT_IMPORTS].isTrue() && Allycs::config[FIX_DIRECT_IMPORTS_UNIVERSAL].isTrue())
		{
			if (iatReferenceScan.numberOfFoundDirectImports() > 0)
			{
				importRebuild.iatReferenceScan = &iatReferenceScan;
				importRebuild.BuildDirectImportsJumpTable = true;
			}
		}

		if (Allycs::config[CREATE_NEW_IAT_IN_SECTION].isTrue())
		{
			importRebuild.iatReferenceScan = &iatReferenceScan;

			DWORD_PTR addressIAT = EditIATAddress.GetValue();
			DWORD sizeIAT = EditIATSize.GetValue();
			importRebuild.enableNewIatInSection(addressIAT, sizeIAT);
		}


		if (importRebuild.rebuildImportTable(newFilePath, importsHandling.moduleList))
		{
			Allycs::windowLog.log(L"Import Rebuild success %s", newFilePath);
		}
		else
		{
			Allycs::windowLog.log(L"Import Rebuild failed %s", selectedFilePath);
			MessageBox(L"Import Rebuild failed", L"Failure", MB_ICONERROR);
		}
	}
}

void MainGui::enableDialogControls(BOOL value)
{
	BOOL valButton = value ? TRUE : FALSE;

	GetDlgItem(IDC_BTN_PICKDLL).EnableWindow(valButton);
	GetDlgItem(IDC_BTN_DUMP).EnableWindow(valButton);
	GetDlgItem(IDC_BTN_FIXDUMP).EnableWindow(valButton);
	GetDlgItem(IDC_BTN_IATAUTOSEARCH).EnableWindow(valButton);
	GetDlgItem(IDC_BTN_GETIMPORTS).EnableWindow(valButton);
	GetDlgItem(IDC_BTN_SUSPECTIMPORTS).EnableWindow(valButton);
	GetDlgItem(IDC_BTN_INVALIDIMPORTS).EnableWindow(valButton);
	GetDlgItem(IDC_BTN_CLEARIMPORTS).EnableWindow(valButton);

	CMenuHandle menu = GetMenu();

	UINT valMenu = value ? MF_ENABLED : MF_GRAYED;

	menu.EnableMenuItem(ID_FILE_DUMP, valMenu);
	menu.EnableMenuItem(ID_FILE_DUMPMEMORY, valMenu);
	menu.EnableMenuItem(ID_FILE_DUMPSECTION, valMenu);
	menu.EnableMenuItem(ID_FILE_FIXDUMP, valMenu);
	menu.EnableMenuItem(ID_IMPORTS_INVALIDATESELECTED, valMenu);
	menu.EnableMenuItem(ID_IMPORTS_CUTSELECTED, valMenu);
	menu.EnableMenuItem(ID_IMPORTS_SAVETREE, valMenu);
	menu.EnableMenuItem(ID_IMPORTS_LOADTREE, valMenu);
	menu.EnableMenuItem(ID_MISC_DLLINJECTION, valMenu);
	menu.EnableMenuItem(ID_MISC_DISASSEMBLER, valMenu);
	menu.GetSubMenu(MenuImportsOffsetTrace).EnableMenuItem(MenuImportsTraceOffsetAllycs, MF_BYPOSITION | valMenu);
	menu.GetSubMenu(MenuImportsOffsetTrace).EnableMenuItem(MenuImportsTraceOffsetImpRec, MF_BYPOSITION | valMenu);

	//not yet implemented
	GetDlgItem(IDC_BTN_AUTOTRACE).EnableWindow(FALSE);
	menu.EnableMenuItem(ID_TRACE_AUTOTRACE, MF_GRAYED);
}

CTreeItem MainGui::findTreeItem(CPoint pt, bool screenCoordinates)
{
	if(screenCoordinates)
	{
		TreeImports.ScreenToClient(&pt);
	}

	UINT flags;
	CTreeItem over = TreeImports.HitTest(pt, &flags);
	if(over)
	{
		if(!(flags & TVHT_ONITEM))
		{
			over.m_hTreeItem = NULL;
		}
	}

	return over;
}

void MainGui::showAboutDialog()
{
	AboutGui dlgAbout;
	dlgAbout.DoModal();
}

void MainGui::showDonateDialog()
{
	DonateGui dlgDonate;
	dlgDonate.DoModal();
}

void MainGui::dllInjectActionHandler()
{
	if(!selectedProcess)
		return;

	WCHAR selectedFilePath[MAX_PATH];
	HMODULE hMod = 0;
	DllInjection dllInjection;

	getCurrentModulePath(stringBuffer, _countof(stringBuffer));
	if (showFileDialog(selectedFilePath, false, NULL, filterDll, NULL, stringBuffer))
	{
		hMod = dllInjection.dllInjection(ProcessAccessHelp::hProcess, selectedFilePath);
		if (hMod && Allycs::config[DLL_INJECTION_AUTO_UNLOAD].isTrue())
		{
			if (!dllInjection.unloadDllInProcess(ProcessAccessHelp::hProcess, hMod))
			{
				Allycs::windowLog.log(L"DLL unloading failed, target %s", selectedFilePath);
			}
		}

		if (hMod)
		{
			Allycs::windowLog.log(L"DLL Injection was successful, target %s", selectedFilePath);
		}
		else
		{
			Allycs::windowLog.log(L"DLL Injection failed, target %s", selectedFilePath);
		}
	}
}

void MainGui::disassemblerActionHandler()
{
	DWORD_PTR oep = EditOEPAddress.GetValue();
	DisassemblerGui disGuiDlg(oep, &apiReader);
	disGuiDlg.DoModal();
}

void MainGui::optionsActionHandler()
{
	OptionsGui dlgOptions;
	dlgOptions.DoModal();
}

void MainGui::clearImportsActionHandler()
{
	importsHandling.clearAllImports();
	updateStatusBar();
}

void MainGui::pluginActionHandler( int menuItem )
{
	if(!selectedProcess)
		return;

	DllInjectionPlugin dllInjectionPlugin;

	std::vector<Plugin> &allycsPluginList = Allycs::plugins.getAllycsPluginList();
	std::vector<Plugin> &imprecPluginList = Allycs::plugins.getImprecPluginList();

	menuItem -= PLUGIN_MENU_BASE_ID;

	dllInjectionPlugin.hProcess = ProcessAccessHelp::hProcess;
	dllInjectionPlugin.apiReader = &apiReader;

	if (menuItem < (int)allycsPluginList.size())
	{
		//allycs plugin
		dllInjectionPlugin.injectPlugin(allycsPluginList[menuItem], importsHandling.moduleList,selectedProcess->imageBase, selectedProcess->imageSize);
	}
	else
	{
#ifndef _WIN64

		menuItem -= (int)allycsPluginList.size();
		//imprec plugin
		dllInjectionPlugin.injectImprecPlugin(imprecPluginList[menuItem], importsHandling.moduleList,selectedProcess->imageBase, selectedProcess->imageSize);

#endif
	}

	importsHandling.scanAndFixModuleList();
	importsHandling.displayAllImports();
	updateStatusBar();
}

bool MainGui::getCurrentModulePath(WCHAR * buffer, size_t bufferSize)
{
	if(!selectedProcess)
		return false;

	if(ProcessAccessHelp::selectedModule)
	{
		wcscpy_s(buffer, bufferSize, ProcessAccessHelp::selectedModule->fullPath);
	}
	else
	{
		wcscpy_s(buffer, bufferSize, selectedProcess->fullPath);
	}

	WCHAR * slash = wcsrchr(buffer, L'\\');
	if(slash)
	{
		*(slash+1) = L'\0';
	}

	return true;
}

void MainGui::checkSuspendProcess()
{
	if (Allycs::config[SUSPEND_PROCESS_FOR_DUMPING].isTrue())
	{
		if (!ProcessAccessHelp::suspendProcess())
		{
			Allycs::windowLog.log(L"Error: Cannot suspend process.");
		}
		else
		{
			isProcessSuspended = true;
			Allycs::windowLog.log(L"Suspending process successful, please resume manually.");
		}
	}
}

void MainGui::setDialogIATAddressAndSize( DWORD_PTR addressIAT, DWORD sizeIAT )
{
	EditIATAddress.SetValue(addressIAT);
	EditIATSize.SetValue(sizeIAT);

	swprintf_s(stringBuffer, L"IAT found:\r\n\r\nStart: " PRINTF_DWORD_PTR_FULL L"\r\nSize: 0x%04X (%d) ", addressIAT, sizeIAT, sizeIAT);
	MessageBox(stringBuffer, L"IAT found", MB_ICONINFORMATION);
}

bool MainGui::isIATOutsidePeImage( DWORD_PTR addressIAT )
{
	DWORD_PTR minAdd = 0, maxAdd = 0;

	if(ProcessAccessHelp::selectedModule)
	{
		minAdd = ProcessAccessHelp::selectedModule->modBaseAddr;
		maxAdd = minAdd + ProcessAccessHelp::selectedModule->modBaseSize;
	}
	else
	{
		minAdd = selectedProcess->imageBase;
		maxAdd = minAdd + selectedProcess->imageSize;
	}

	if (addressIAT > minAdd && addressIAT < maxAdd)
	{
		return false; //inside pe image
	}
	else
	{
		return true; //outside pe image, requires rebasing iat
	}
}

bool MainGui::getCurrentDefaultDumpFilename( WCHAR * buffer, size_t bufferSize )
{
    if(!selectedProcess)
        return false;

    WCHAR * fullPath;

    if(ProcessAccessHelp::selectedModule)
    {
        fullPath = ProcessAccessHelp::selectedModule->fullPath;
    }
    else
    {
        fullPath = selectedProcess->fullPath;
    }

    WCHAR * temp = wcsrchr(fullPath, L'\\');
    if(temp)
    {
        temp++;
        wcscpy_s(buffer, bufferSize, temp);

        temp = wcsrchr(buffer, L'.');
        if (temp)
        {
            *temp = 0;

            if(ProcessAccessHelp::selectedModule)
            {
                wcscat_s(buffer, bufferSize, L"_dump.dll");
            }
            else
            {
                wcscat_s(buffer, bufferSize, L"_dump.exe");
            }
        }
        

        return true;
    }

    return false;
}

void MainGui::darkModeActionHandler()
{
	isDarkModeEnabled = !isDarkModeEnabled;
	updateDarkModeButton();
	
	// Save the setting
	Allycs::config[DARK_MODE].setBool(isDarkModeEnabled);
	Allycs::config.saveConfiguration();

	// Apply dark mode based on the current state
	applyDarkMode(isDarkModeEnabled);
}

void MainGui::applyDarkMode(bool enable)
{
	// Define colors for dark mode
	COLORREF darkBkColor = RGB(32, 32, 32);
	COLORREF darkTextColor = RGB(255, 255, 255);
	COLORREF darkEditBkColor = RGB(45, 45, 45);
	
	// Define colors for light mode (system default)
	COLORREF lightBkColor = ::GetSysColor(COLOR_WINDOW);
	COLORREF lightTextColor = ::GetSysColor(COLOR_WINDOWTEXT);
	
	// Set colors based on mode
	COLORREF bkColor = enable ? darkBkColor : lightBkColor;
	COLORREF textColor = enable ? darkTextColor : lightTextColor;
	
	// Apply to tree view with specific styling for dark mode
	TreeImports.SetBkColor(enable ? darkEditBkColor : lightBkColor);
	TreeImports.SetTextColor(textColor);
	
	// Apply to list box
	if (ListLog.IsWindow())
	{
		// For CListBox, we need to invalidate it to trigger WM_CTLCOLORLISTBOX
		ListLog.InvalidateRect(NULL, TRUE);
	}
	
	// Apply to combo box
	if (ComboProcessList.IsWindow())
	{
		ComboProcessList.InvalidateRect(NULL, TRUE);
	}
	
	// Apply to edit controls
	if (EditOEPAddress.IsWindow()) EditOEPAddress.InvalidateRect(NULL, TRUE);
	if (EditIATAddress.IsWindow()) EditIATAddress.InvalidateRect(NULL, TRUE);
	if (EditIATSize.IsWindow()) EditIATSize.InvalidateRect(NULL, TRUE);
	
	// Explicitly invalidate all group boxes to ensure their text is redrawn
	GetDlgItem(IDC_GROUP_ATTACH).InvalidateRect(NULL, TRUE);
	GetDlgItem(IDC_GROUP_IMPORTS).InvalidateRect(NULL, TRUE);
	GetDlgItem(IDC_GROUP_IATINFO).InvalidateRect(NULL, TRUE);
	GetDlgItem(IDC_GROUP_ACTIONS).InvalidateRect(NULL, TRUE);
	GetDlgItem(IDC_GROUP_DUMP).InvalidateRect(NULL, TRUE);
	GetDlgItem(IDC_GROUP_LOG).InvalidateRect(NULL, TRUE);
	
	// Force a complete redraw of all controls
	RedrawWindow(NULL, NULL, RDW_INVALIDATE | RDW_ALLCHILDREN | RDW_ERASE | RDW_UPDATENOW | RDW_FRAME);
	
	// Update the status bar
	updateStatusBar();
	
	if (enable)
	{
		SetWindowTheme(GetDlgItem(IDC_GROUP_ATTACH), L"", L"");
		SetWindowTheme(GetDlgItem(IDC_GROUP_IMPORTS), L"", L"");
		SetWindowTheme(GetDlgItem(IDC_GROUP_IATINFO), L"", L"");
		SetWindowTheme(GetDlgItem(IDC_GROUP_ACTIONS), L"", L"");
		SetWindowTheme(GetDlgItem(IDC_GROUP_DUMP), L"", L"");
		SetWindowTheme(GetDlgItem(IDC_GROUP_LOG), L"", L"");
	}
	else
	{
		// Restore normal theme if needed
		SetWindowTheme(GetDlgItem(IDC_GROUP_ATTACH), NULL, NULL);
		SetWindowTheme(GetDlgItem(IDC_GROUP_IMPORTS), NULL, NULL);
		SetWindowTheme(GetDlgItem(IDC_GROUP_IATINFO), NULL, NULL);
		SetWindowTheme(GetDlgItem(IDC_GROUP_ACTIONS), NULL, NULL);
		SetWindowTheme(GetDlgItem(IDC_GROUP_DUMP), NULL, NULL);
		SetWindowTheme(GetDlgItem(IDC_GROUP_LOG), NULL, NULL);
	}
}

void MainGui::updateDarkModeButton()
{
	CWindow darkModeBtn = GetDlgItem(IDC_BTN_DARKMODE);
	darkModeBtn.SetWindowText(isDarkModeEnabled ? L"Light Mode" : L"Dark Mode");
}
BOOL MainGui::OnEraseBkgnd(CDCHandle dc)
{
	if (isDarkModeEnabled)
	{
		CRect rect;
		GetClientRect(&rect);
		dc.FillSolidRect(&rect, RGB(32, 32, 32));
		return TRUE;
	}
	SetMsgHandled(FALSE);
	return FALSE;
}

