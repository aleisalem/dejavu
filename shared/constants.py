#!/usr/bin/python

import re

activityActions = ["touch", "type", "press", "drag"]

androidPermissions = [u'android.permission.ACCESS_CACHE_FILESYSTEM', u'android.permission.ACCESS_COARES_LOCATION', u'android.permission.ACCESS_COARSE', u'android.permission.ACCESS_COARSE_LOCATION', u'android.permission.ACCESS_COARSE_UPDATES', u'android.permission.ACCESS_COURSE_LOCATION', u'android.permission.ACCESS_DOWNLOAD_MANAGER', u'android.permission.ACCESS_DOWNLOAD_MANAGER_ADVANCED', u'android.permission.ACCESS_DRM', u'android.permission.ACCESS_FIND_LOCATION', u'android.permission.ACCESS_FINE_LOCATION', u'android.permission.ACCESS_GPS', u'android.permission.ACCESS_LOCATION', u'android.permission.ACCESS_LOCATION_EXTRA_COMMANDS', u'android.permission.ACCESS_MOCK_LOCATION', u'android.permission.ACCESS_NETWORK_STATE', u'android.permission.ACCESS_PHONE_STATE', u'android.permission.ACCESS_SUPERUSER', u'android.permission.ACCESS_SURFACE_FLINGER', u'android.permission.ACCESS_WIFI_STATE', u'android.permission.ACCESS_WIMAX_STATE', u'android.permission.ACCOUNT_MANAGER', u'android.permission.ACESS_COARSE_LOCATION', u'android.permission.AUTHENTICATE_ACCOUNTS', u'android.permission.BACKUP', u'android.permission.BAIDU_LOCATION_SERVICE', u'android.permission.BATTERY_STATS', u'android.permission.BIND_APPWIDGET', u'android.permission.BIND_WALLPAPER', u'android.permission.BLUETOOTH', u'android.permission.BLUETOOTH_ADMIN', u'android.permission.BROADCAST_PACKAGE_REMOVED', u'android.permission.BROADCAST_STICKY', u'android.permission.CALL_PHONE', u'android.permission.CALL_PRIVILEGED', u'android.permission.CAMERA', u'android.permission.CHANGE_COMPONENT_ENABLED_STATE', u'android.permission.CHANGE_CONFIGURATION', u'android.permission.CHANGE_NETWORK_SATET', u'android.permission.CHANGE_NETWORK_STATE', u'android.permission.CHANGE_WIFI_MULTICAST_STATE', u'android.permission.CHANGE_WIFI_STATE', u'android.permission.CHANGE_WIMAX_STATE', u'android.permission.CLEAR_APP_CACHE', u'android.permission.CLEAR_APP_USER_DATA', u'android.permission.CONFIGURE_SIP', u'android.permission.CONTROL_LOCATION_UPDATES', u'android.permission.DELETE_CACHE_FILES', u'android.permission.DELETE_PACKAGES', u'android.permission.DEVICE_POWER', u'android.permission.DISABLE_KEYGUARD', u'android.permission.DOWNLOAD_WITHOUT_NOTIFICATION', u'android.permission.EXPAND_STATUS_BAR', u'android.permission.FLASHLIGHT', u'android.permission.FORCE_STOP_PACKAGES', u'android.permission.FULLSCREEN', u'android.permission.GET_ACCOUNTS', u'android.permission.GET_PACKAGE_SIZE', u'android.permission.GET_TASKS', u'android.permission.INSTALL_DRM', u'android.permission.INSTALL_LOCATION_PROVIDER', u'android.permission.INSTALL_PACKA', u'android.permission.INSTALL_PACKAGES', u'android.permission.INTERACT_ACROSS_USERS_FULL', u'android.permission.INTERNET', u'android.permission.KILL_BACKGROUND_PROCESSES', u'android.permission.LOCATION', u'android.permission.MANAGE_ACCOUNTS', u'android.permission.MODIFY_AUDIO_SETTINGS', u'android.permission.MODIFY_PHONE_STATE', u'android.permission.MOUNT_FORMAT_FILESYSTEMS', u'android.permission.MOUNT_UNMOUNT_FILESYSTEMS', u'android.permission.NFC', u'android.permission.PERSISTENT_ACTIVITY', u'android.permission.PROCESS_OUTGOING_CALLS', u'android.permission.READ_CALENDAR', u'android.permission.READ_CALL_LOG', u'android.permission.READ_CONTACTS', u'android.permission.READ_EXTERNAL_STORAGE', u'android.permission.READ_FRAME_BUFFER', u'android.permission.READ_INPUT_STATE', u'android.permission.READ_LOGS', u'android.permission.READ_MMS', u'android.permission.READ_OWNER_DATA', u'android.permission.READ_PHONE_STATE', u'android.permission.READ_PROFILE', u'android.permission.READ_SECURE_SETTINGS', u'android.permission.READ_SETTINGS', u'android.permission.READ_SMS', u'android.permission.READ_SOCIAL_STREAM', u'android.permission.READ_SYNC_SETTINGS', u'android.permission.READ_SYNC_STATS', u'android.permission.READ_USER_DICTIONARY', u'android.permission.RECEIVE_BOOT_COMPLETED', u'android.permission.RECEIVE_MMS', u'android.permission.RECEIVE_SMS', u'android.permission.RECEIVE_USER_PRESENT', u'android.permission.RECEIVE_WAP_PUSH', u'android.permission.RECORD_AUDIO', u'android.permission.RECORD_VIDEO', u'android.permission.REORDER_TASKS', u'android.permission.RESTART_PACKAGE', u'android.permission.RESTART_PACKAGES', u'android.permission.RUN_INSTRUMENTATION', u'android.permission.SENDTO', u'android.permission.SEND_DOWNLOAD_COMPLETED_INTENTS', u'android.permission.SEND_SMS', u'android.permission.SET_DEBUG_APP', u'android.permission.SET_ORIENTATION', u'android.permission.SET_PREFERRED_APPLICATIONS', u'android.permission.SET_TIME_ZONE', u'android.permission.SET_WALLPAPER', u'android.permission.SET_WALLPAPER_HINT', u'android.permission.SET_WALLPAPER_HINTS', u'android.permission.SHAKE', u'android.permission.START_BACKGROUND_SERVICE', u'android.permission.STATUS_BAR', u'android.permission.STORAGE', u'android.permission.SUBSCRIBED_FEEDS_READ', u'android.permission.SUBSCRIBED_FEEDS_WRITE', u'android.permission.SYSTEM_ALERT_WINDOW', u'android.permission.SYSTEM_OVERLAY_WINDOW', u'android.permission.UPDATE_DEVICE_STATS', u'android.permission.USE_CREDENTIALS', u'android.permission.USE_SIP', u'android.permission.VIBRATE', u'android.permission.WAKE_LOCK', u'android.permission.WRITE_APN_SETTINGS', u'android.permission.WRITE_CALENDAR', u'android.permission.WRITE_CONTACTS', u'android.permission.WRITE_EXTERNALS_STORAGE', u'android.permission.WRITE_EXTERNAL_STORAGE', u'android.permission.WRITE_EXTRENAL_STORAGE', u'android.permission.WRITE_INTERNAL_STORAGE', u'android.permission.WRITE_MEDIA_STORAGE', u'android.permission.WRITE_OWNER_DATA', u'android.permission.WRITE_SECURE_SETTINGS', u'android.permission.WRITE_SETTINGS', u'android.permission.WRITE_SMS', u'android.permission.WRITE_SOCIAL_STREAM', u'android.permission.WRITE_SYNC_SETTINGS', u'android.permission.WRITE_SYNC_STATS', u'android.permission.WRITE_USER_DICTIONARY', u'android.permission.android.hardware.sensor.accelerometer', u'android.permission.complete']

allCompilers = ['dx', 'dx (possible dexmerge)', 'dexlib 1.x', 'dexlib 2.x', 'Jack 4.x', 'n/a']

allVirusTotalKeys = [u'accessed_files', u'accessed_uris', u'additional', u'contacted_urls', u'database_opened', u'deleted_files', u'dynamically_called_methods', u'dynamically_loaded_classes', u'external_programs', u'killed_packages', u'opened_files', u'permissions_checked', u'sandbox-version', u'sms_sent', u'started_activities', u'started_receivers', u'started_services', u'stopped_services']

argumentsRegex = { 
    "date": re.compile('(?:(?<!\:)(?<!\:\d)[0-3]?\d(?:st|nd|rd|th)?\s+(?:of\s+)?(?:jan\.?|january|feb\.?|february|mar\.?|march|apr\.?|april|may|jun\.?|june|jul\.?|july|aug\.?|august|sep\.?|september|oct\.?|october|nov\.?|november|dec\.?|december)|(?:jan\.?|january|feb\.?|february|mar\.?|march|apr\.?|april|may|jun\.?|june|jul\.?|july|aug\.?|august|sep\.?|september|oct\.?|october|nov\.?|november|dec\.?|december)\s+(?<!\:)(?<!\:\d)[0-3]?\d(?:st|nd|rd|th)?)(?:\,)?\s*(?:\d{4})?|[0-3]?\d[-\./][0-3]?\d[-\./]\d{2,4}', re.IGNORECASE),
    "time": re.compile('\d{1,2}:\d{2} ?(?:[ap]\.?m\.?)?|\d[ap]\.?m\.?', re.IGNORECASE),
    "phone": re.compile('''((?:(?<![\d-])(?:\+?\d{1,3}[-.\s*]?)?(?:\(?\d{3}\)?[-.\s*]?)?\d{3}[-.\s*]?\d{4}(?![\d-]))|(?:(?<![\d-])(?:(?:\(\+?\d{2}\))|(?:\+?\d{2}))\s*\d{2}\s*\d{3}\s*\d{4}(?![\d-])))'''),
    "phones_with_exts": re.compile('((?:(?:\+?1\s*(?:[.-]\s*)?)?(?:\(\s*(?:[2-9]1[02-9]|[2-9][02-8]1|[2-9][02-8][02-9])\s*\)|(?:[2-9]1[02-9]|[2-9][02-8]1|[2-9][02-8][02-9]))\s*(?:[.-]\s*)?)?(?:[2-9]1[02-9]|[2-9][02-9]1|[2-9][02-9]{2})\s*(?:[.-]\s*)?(?:[0-9]{4})(?:\s*(?:#|x\.?|ext\.?|extension)\s*(?:\d+)?))', re.IGNORECASE), 
    "link": re.compile('(?i)((?:https?://|www\d{0,3}[.])?[a-z0-9.\-]+[.](?:(?:international)|(?:construction)|(?:contractors)|(?:enterprises)|(?:photography)|(?:immobilien)|(?:management)|(?:technology)|(?:directory)|(?:education)|(?:equipment)|(?:institute)|(?:marketing)|(?:solutions)|(?:builders)|(?:clothing)|(?:computer)|(?:democrat)|(?:diamonds)|(?:graphics)|(?:holdings)|(?:lighting)|(?:plumbing)|(?:training)|(?:ventures)|(?:academy)|(?:careers)|(?:company)|(?:domains)|(?:florist)|(?:gallery)|(?:guitars)|(?:holiday)|(?:kitchen)|(?:recipes)|(?:shiksha)|(?:singles)|(?:support)|(?:systems)|(?:agency)|(?:berlin)|(?:camera)|(?:center)|(?:coffee)|(?:estate)|(?:kaufen)|(?:luxury)|(?:monash)|(?:museum)|(?:photos)|(?:repair)|(?:social)|(?:tattoo)|(?:travel)|(?:viajes)|(?:voyage)|(?:build)|(?:cheap)|(?:codes)|(?:dance)|(?:email)|(?:glass)|(?:house)|(?:ninja)|(?:photo)|(?:shoes)|(?:solar)|(?:today)|(?:aero)|(?:arpa)|(?:asia)|(?:bike)|(?:buzz)|(?:camp)|(?:club)|(?:coop)|(?:farm)|(?:gift)|(?:guru)|(?:info)|(?:jobs)|(?:kiwi)|(?:land)|(?:limo)|(?:link)|(?:menu)|(?:mobi)|(?:moda)|(?:name)|(?:pics)|(?:pink)|(?:post)|(?:rich)|(?:ruhr)|(?:sexy)|(?:tips)|(?:wang)|(?:wien)|(?:zone)|(?:biz)|(?:cab)|(?:cat)|(?:ceo)|(?:com)|(?:edu)|(?:gov)|(?:int)|(?:mil)|(?:net)|(?:onl)|(?:org)|(?:pro)|(?:red)|(?:tel)|(?:uno)|(?:xxx)|(?:ac)|(?:ad)|(?:ae)|(?:af)|(?:ag)|(?:ai)|(?:al)|(?:am)|(?:an)|(?:ao)|(?:aq)|(?:ar)|(?:as)|(?:at)|(?:au)|(?:aw)|(?:ax)|(?:az)|(?:ba)|(?:bb)|(?:bd)|(?:be)|(?:bf)|(?:bg)|(?:bh)|(?:bi)|(?:bj)|(?:bm)|(?:bn)|(?:bo)|(?:br)|(?:bs)|(?:bt)|(?:bv)|(?:bw)|(?:by)|(?:bz)|(?:ca)|(?:cc)|(?:cd)|(?:cf)|(?:cg)|(?:ch)|(?:ci)|(?:ck)|(?:cl)|(?:cm)|(?:cn)|(?:co)|(?:cr)|(?:cu)|(?:cv)|(?:cw)|(?:cx)|(?:cy)|(?:cz)|(?:de)|(?:dj)|(?:dk)|(?:dm)|(?:do)|(?:dz)|(?:ec)|(?:ee)|(?:eg)|(?:er)|(?:es)|(?:et)|(?:eu)|(?:fi)|(?:fj)|(?:fk)|(?:fm)|(?:fo)|(?:fr)|(?:ga)|(?:gb)|(?:gd)|(?:ge)|(?:gf)|(?:gg)|(?:gh)|(?:gi)|(?:gl)|(?:gm)|(?:gn)|(?:gp)|(?:gq)|(?:gr)|(?:gs)|(?:gt)|(?:gu)|(?:gw)|(?:gy)|(?:hk)|(?:hm)|(?:hn)|(?:hr)|(?:ht)|(?:hu)|(?:id)|(?:ie)|(?:il)|(?:im)|(?:in)|(?:io)|(?:iq)|(?:ir)|(?:is)|(?:it)|(?:je)|(?:jm)|(?:jo)|(?:jp)|(?:ke)|(?:kg)|(?:kh)|(?:ki)|(?:km)|(?:kn)|(?:kp)|(?:kr)|(?:kw)|(?:ky)|(?:kz)|(?:la)|(?:lb)|(?:lc)|(?:li)|(?:lk)|(?:lr)|(?:ls)|(?:lt)|(?:lu)|(?:lv)|(?:ly)|(?:ma)|(?:mc)|(?:md)|(?:me)|(?:mg)|(?:mh)|(?:mk)|(?:ml)|(?:mm)|(?:mn)|(?:mo)|(?:mp)|(?:mq)|(?:mr)|(?:ms)|(?:mt)|(?:mu)|(?:mv)|(?:mw)|(?:mx)|(?:my)|(?:mz)|(?:na)|(?:nc)|(?:ne)|(?:nf)|(?:ng)|(?:ni)|(?:nl)|(?:no)|(?:np)|(?:nr)|(?:nu)|(?:nz)|(?:om)|(?:pa)|(?:pe)|(?:pf)|(?:pg)|(?:ph)|(?:pk)|(?:pl)|(?:pm)|(?:pn)|(?:pr)|(?:ps)|(?:pt)|(?:pw)|(?:py)|(?:qa)|(?:re)|(?:ro)|(?:rs)|(?:ru)|(?:rw)|(?:sa)|(?:sb)|(?:sc)|(?:sd)|(?:se)|(?:sg)|(?:sh)|(?:si)|(?:sj)|(?:sk)|(?:sl)|(?:sm)|(?:sn)|(?:so)|(?:sr)|(?:st)|(?:su)|(?:sv)|(?:sx)|(?:sy)|(?:sz)|(?:tc)|(?:td)|(?:tf)|(?:tg)|(?:th)|(?:tj)|(?:tk)|(?:tl)|(?:tm)|(?:tn)|(?:to)|(?:tp)|(?:tr)|(?:tt)|(?:tv)|(?:tw)|(?:tz)|(?:ua)|(?:ug)|(?:uk)|(?:us)|(?:uy)|(?:uz)|(?:va)|(?:vc)|(?:ve)|(?:vg)|(?:vi)|(?:vn)|(?:vu)|(?:wf)|(?:ws)|(?:ye)|(?:yt)|(?:za)|(?:zm)|(?:zw))(?:/[^\s()<>]+[^\s`!()\[\]{};:\'".,<>?\xab\xbb\u201c\u201d\u2018\u2019])?)', re.IGNORECASE),
    "email": re.compile("([a-z0-9!#$%&'*+\/=?^_`{|.}~-]+@(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)", re.IGNORECASE),
    "ip": re.compile('(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)', re.IGNORECASE),
    "ipv6": re.compile('\s*(?!.*::.*::)(?:(?!:)|:(?=:))(?:[0-9a-f]{0,4}(?:(?<=::)|(?<!::):)){6}(?:[0-9a-f]{0,4}(?:(?<=::)|(?<!::):)[0-9a-f]{0,4}(?:(?<=::)|(?<!:)|(?<=:)(?<!::):)|(?:25[0-4]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-4]|2[0-4]\d|1\d\d|[1-9]?\d)){3})\s*', re.VERBOSE|re.IGNORECASE|re.DOTALL),
    "price": re.compile('[$]\s?[+-]?[0-9]{1,3}(?:(?:,?[0-9]{3}))*(?:\.[0-9]{1,2})?'),
    "hex_color": re.compile('(#(?:[0-9a-fA-F]{8})|#(?:[0-9a-fA-F]{3}){1,2})\\b'),
    "credit_card": re.compile('((?:(?:\\d{4}[- ]?){3}\\d{4}|\\d{15,16}))(?![\\d])'),
    "btc_address": re.compile('(?<![a-km-zA-HJ-NP-Z0-9])[13][a-km-zA-HJ-NP-Z0-9]{26,33}(?![a-km-zA-HJ-NP-Z0-9])'),
    "street_address": re.compile('\d{1,4} [\w\s]{1,20}(?:street|st|avenue|ave|road|rd|highway|hwy|square|sq|trail|trl|drive|dr|court|ct|park|parkway|pkwy|circle|cir|boulevard|blvd)\W?(?=\s|$)', re.IGNORECASE),
    "zip_code": re.compile(r'\b\d{5}(?:[-\s]\d{4})?\b'),
    "po_box": re.compile(r'P\.? ?O\.? Box \d+', re.IGNORECASE),
    "md5_hash": re.compile(r"([a-fA-F\d]{32})", re.IGNORECASE),
    "sha1_hash": re.compile(r"([a-fA-F\d]{40})", re.IGNORECASE),
    "sha256_hash": re.compile(r"([a-fA-F\d]{64})", re.IGNORECASE),
    "sha512_hash": re.compile(r"([a-fA-F\d]{128})", re.IGNORECASE)
}

droidmonDefaultClasses = [u'android.telephony.TelephonyManager', u'android.net.wifi.WifiInfo', u'android.os.Debug', u'android.app.SharedPreferencesImpl$EditorImpl', u'android.content.ContentValues', u'java.net.URL', u'org.apache.http.impl.client.AbstractHttpClient', u'android.app.ContextImpl', u'android.app.ActivityThread', u'android.app.Activity', u'dalvik.system.BaseDexClassLoader', u'dalvik.system.DexFile', u'dalvik.system.DexClassLoader', u'dalvik.system.PathClassLoader', u'java.lang.reflect.Method', u'javax.crypto.spec.SecretKeySpec', u'javax.crypto.Cipher', u'javax.crypto.Mac', u'android.app.ApplicationPackageManager', u'android.app.NotificationManager', u'android.util.Base64', u'android.net.ConnectivityManager', u'android.content.BroadcastReceiver', u'android.telephony.SmsManager', u'java.lang.Runtime', u'java.lang.ProcessBuilder', u'java.io.FileOutputStream', u'java.io.FileInputStream', u'android.app.ActivityManager', u'android.os.Process', u'android.content.ContentResolver', u'android.accounts.AccountManager', u'android.location.Location', u'android.media.AudioRecord', u'android.media.MediaRecorder', u'android.os.SystemProperties', u'libcore.io.IoBridge']

droidmonDefaultMethods = [u'getDeviceId', u'getSubscriberId', u'getLine1Number', u'getNetworkOperator', u'getNetworkOperatorName', u'getSimOperatorName', u'getMacAddress', u'getSimCountryIso', u'getSimSerialNumber', u'getNetworkCountryIso', u'getDeviceSoftwareVersion', u'isDebuggerConnected', u'putString', u'putBoolean', u'putInt', u'putLong', u'putFloat', u'put', u'openConnection', u'execute', u'registerReceiver', u'handleReceiver', u'startActivity', u'findResource', u'findLibrary', u'loadDex',u'findResources', u'loadClass', u'invoke', u'doFinal', u'setComponentEnabledSetting', u'notify', u'decode', u'listen', u'encode', u'encodeToString', u'setMobileDataEnabled', u'abortBroadcast', u'sendTextMessage', u'sendMultipartTextMessage', u'exec', u'start', u'write', u'read', u'killBackgroundProcesses', u'killProcess', u'query', u'registerContentObserver', u'insert', u'getAccountsByType', u'getAccounts', u'getLatitude', u'getLongitude', u'delete', u'startRecording', u'get', u'getInstalledPackages', u'open']

keyEvents = ["KEYCODE_UNKNOWN", "KEYCODE_MENU", "KEYCODE_SOFT_RIGHT", "KEYCODE_HOME", "KEYCODE_BACK", "KEYCODE_CALL", "KEYCODE_ENDCALL", "KEYCODE_0", "KEYCODE_1", "KEYCODE_2", "KEYCODE_3", "KEYCODE_4", "KEYCODE_5", "KEYCODE_6", "KEYCODE_7", "KEYCODE_8", "KEYCODE_9", "KEYCODE_STAR", "KEYCODE_POUND", "KEYCODE_DPAD_UP", "KEYCODE_DPAD_DOWN", "KEYCODE_DPAD_LEFT", "KEYCODE_DPAD_RIGHT", "KEYCODE_DPAD_CENTER", "KEYCODE_VOLUME_UP", "KEYCODE_VOLUME_DOWN", "KEYCODE_POWER", "KEYCODE_CAMERA", "KEYCODE_CLEAR", "KEYCODE_A", "KEYCODE_B", "KEYCODE_C", "KEYCODE_D", "KEYCODE_E", "KEYCODE_F", "KEYCODE_G", "KEYCODE_H", "KEYCODE_I", "KEYCODE_J", "KEYCODE_K", "KEYCODE_L", "KEYCODE_M", "KEYCODE_N", "KEYCODE_O", "KEYCODE_P", "KEYCODE_Q", "KEYCODE_R", "KEYCODE_S", "KEYCODE_T", "KEYCODE_U", "KEYCODE_V", "KEYCODE_W", "KEYCODE_X", "KEYCODE_Y", "KEYCODE_Z", "KEYCODE_COMMA", "KEYCODE_PERIOD", "KEYCODE_ALT_LEFT", "KEYCODE_ALT_RIGHT", "KEYCODE_SHIFT_LEFT", "KEYCODE_SHIFT_RIGHT", "KEYCODE_TAB", "KEYCODE_SPACE", "KEYCODE_SYM", "KEYCODE_EXPLORER", "KEYCODE_ENVELOPE", "KEYCODE_ENTER", "KEYCODE_DEL", "KEYCODE_GRAVE", "KEYCODE_MINUS", "KEYCODE_EQUALS", "KEYCODE_LEFT_BRACKET", "KEYCODE_RIGHT_BRACKET", "KEYCODE_BACKSLASH", "KEYCODE_SEMICOLON", "KEYCODE_APOSTROPHE", "KEYCODE_SLASH", "KEYCODE_AT", "KEYCODE_NUM", "KEYCODE_HEADSETHOOK", "KEYCODE_FOCUS", "KEYCODE_PLUS", "KEYCODE_MENU", "KEYCODE_NOTIFICATION", "KEYCODE_SEARCH", "TAG_LAST_KEYCODE"]

keyEventTypes = ["DOWN", "UP", "DOWN_AND_UP"]

sensitiveAPICalls = {"android.content.ContextWrapper": ["bindService", "deleteDatabase", "deleteFile", "deleteSharedPreferences", "getSystemService", "openFileInput", "startService", "stopService", "unbindService", "unregisterReceiver"], "android.accounts.AccountManager": ["clearPassword", "getAccounts", "getPassword", "peekAuthToken", "setAuthToken", "setPassword"], "android.app.Activity": ["startActivity", "setContentView", "setVisible", "takeKeyEvents"], "android.app.DownloadManager": ["addCompletedDownload", "enqueue", "getUriForDownloadedFile", "openDownloadedFile", "query"], "android.app.IntentService": ["onStartCommand"], "android.content.ContentResolver": ["insert", "openFileDescriptor", "query", "update"], "android.content.pm.PackageInstaller": ["uninstall"], "android.database.sqlite.SQLiteDatabase": ["execSQL", "insert", "insertOrThrow", "openDatabase", "query", "rawQuery", "replace", "update"], "android.hardware.Camera": ["open", "reconnect", "release", "startPreview", "stopPreview", "takePicture"], "android.hardware.display.DisplayManager": ["getDisplay", "getDisplays"], "android.location.Location": ["getLatitude", "getLongitude"], "android.media.AudioRecord": ["read", "startRecording", "stop"], "android.media.MediaRecorder": ["prepare", "setCamera", "start", "stop"], "android.net.Network": ["bindSocket", "openConnection"], "android.net.NetworkInfo": ["isAvailable", "isConnected", "isRoaming"], "android.net.wifi.WifiInfo": ["getMacAddress", "getSSID"], "android.net.wifi.WifiManager": ["disconnect", "getScanResults", "getWifiState", "reconnect", "startScan"], "android.os.Process": ["killProcess"], "android.os.PowerManager": ["isInteractive", "isScreenOn", "reboot"], "android.telephony.SmsManager": ["sendDataMessage", "sendTextMessage"], "android.widget.Toast": ["makeText"], "dalvik.system.DexClassLoader": ["loadClass"], "dalvik.system.PathClassLoader": ["loadClass"], "java.lang.class": ["forName", "getClassLoader", "getClasses", "getField", "getFields", "getMethods", "getMethod", "getName"], "java.lang.reflect.Method": ["invoke"], "java.net.HttpCookie": ["getName", "getPath", "getSecure", "getValue", "parse", "setPath", "setSecure", "setValue"], "java.net.URL.openConnection": ["openConnection", "openStream"]}

staticCategories = [u'binary', u'crypto', u'dynamic', u'network', u'sms', u'telephony']

staticPackages = [u'a.a.a.a.a.h', u'aDn', u'aLL', u'android.content.ContentValues', u'android.content.Intent', u'android.content.SharedPreferences', u'android.content.SharedPreferences$Editor', u'android.database.sqlite.SQLiteDatabase', u'android.os.Bundle', u'android.os.Process', u'android.telephony.SmsManager', u'android.telephony.TelephonyManager', u'android.util.Log', u'apV', u'base.tina.external.encrypt.TinaCrypt', u'ch.bitforge.android.orbital.Encrypter', u'cn.emagsoftware.gamebilling.DesUtils', u'cn.emagsoftware.sdk.util.DESEncode', u'cn.emagsoftware.sdk.util.DESUtils', u'cn.xs8.app.reader.util.DesUtils', u'cn.xs8.app.utils.DesUtils', u'cn.yahoo.asxhl2007.uiframework.utils.MD5', u'dalvik.system.DexClassLoader', u'dalvik.system.DexFile', u'dalvik.system.PathClassLoader', u'egame.terminal.feesmslib.jni.SmsProtocol', u'java.io.IOException', u'java.lang.Exception', u'java.lang.IllegalArgumentException', u'java.lang.IllegalStateException', u'java.lang.Process', u'java.lang.ProcessBuilder', u'java.lang.Runtime', u'java.lang.String', u'java.lang.StringBuffer', u'java.lang.StringBuilder', u'java.lang.System', u'java.net.HttpURLConnection', u'java.net.JarURLConnection', u'java.net.ServerSocket', u'java.net.Socket', u'java.net.URI', u'java.net.URL', u'java.security.InvalidKeyException', u'java.security.InvalidParameterException', u'java.security.spec.DSAParameterSpec', u'java.security.spec.DSAPrivateKeySpec', u'java.security.spec.DSAPublicKeySpec', u'java.security.spec.ECFieldF2m', u'java.security.spec.ECFieldFp', u'java.security.spec.ECGenParameterSpec', u'java.security.spec.ECParameterSpec', u'java.security.spec.ECPoint', u'java.security.spec.ECPrivateKeySpec', u'java.security.spec.ECPublicKeySpec', u'java.security.spec.EllipticCurve', u'java.security.spec.InvalidKeySpecException', u'java.security.spec.InvalidParameterSpecException', u'java.security.spec.MGF1ParameterSpec', u'java.security.spec.PKCS8EncodedKeySpec', u'java.security.spec.PSSParameterSpec', u'java.security.spec.RSAKeyGenParameterSpec', u'java.security.spec.RSAPrivateCrtKeySpec', u'java.security.spec.RSAPrivateKeySpec', u'java.security.spec.RSAPublicKeySpec', u'java.security.spec.X509EncodedKeySpec', u'java.util.HashMap', u'java.util.Hashtable', u'java.util.Map', u'java.util.Properties', u'java.util.TreeMap', u'java.util.logging.Logger', u'java.util.zip.ZipException', u'javax.bluetooth.BluetoothConnectionException', u'javax.crypto.BadPaddingException', u'javax.crypto.Cipher', u'javax.crypto.CipherInputStream', u'javax.crypto.CipherOutputStream', u'javax.crypto.CipherSpi', u'javax.crypto.EncryptedPrivateKeyInfo', u'javax.crypto.IllegalBlockSizeException', u'javax.crypto.KeyAgreement', u'javax.crypto.KeyAgreementSpi', u'javax.crypto.KeyGenerator', u'javax.crypto.KeyGeneratorSpi', u'javax.crypto.Mac', u'javax.crypto.MacSpi', u'javax.crypto.NoSuchPaddingException', u'javax.crypto.NullCipher', u'javax.crypto.SealedObject', u'javax.crypto.SecretKey', u'javax.crypto.SecretKeyFactory', u'javax.crypto.SecretKeyFactorySpi', u'javax.crypto.ShortBufferException', u'javax.crypto.interfaces.DHKey', u'javax.crypto.interfaces.DHPrivateKey', u'javax.crypto.interfaces.DHPublicKey', u'javax.crypto.interfaces.PBEKey', u'javax.crypto.spec.DESKeySpec', u'javax.crypto.spec.DESedeKeySpec', u'javax.crypto.spec.DHGenParameterSpec', u'javax.crypto.spec.DHParameterSpec', u'javax.crypto.spec.DHPrivateKeySpec', u'javax.crypto.spec.DHPublicKeySpec', u'javax.crypto.spec.IvParameterSpec', u'javax.crypto.spec.OAEPParameterSpec', u'javax.crypto.spec.PBEKeySpec', u'javax.crypto.spec.PBEParameterSpec', u'javax.crypto.spec.PSource$PSpecified', u'javax.crypto.spec.RC2ParameterSpec', u'javax.crypto.spec.RC5ParameterSpec', u'javax.crypto.spec.SecretKeySpec', u'jcifs.util.DES', u'jp.co.cayto.appc.sdk.android.utils.CipherControler', u'jp.colopl.util.Crypto', u'kellinwood.security.zipsigner.ZipSigner', u'kellinwood.security.zipsigner.optional.JKS', u'kr.co.cashslide.EncryptManager', u'mhealth.game.SimpleCrypto', u'miuipub.net.SecureRequest', u'miuipub.net.exception.AccessDeniedException', u'miuipub.net.exception.CipherException', u'miuipub.net.exception.InvalidResponseException', u'mm.purchasesdk.core.l.e', u'mm.purchasesdk.fingerprint.IdentifyApp', u'mm.sms.purchasesdk.fingerprint.IdentifyApp', u'mm.yp.purchasesdk.fingerprint.IdentifyApp', u'neo.skeleton.base.Coder', u'neo.skeleton.base.Coder$CoderException', u'net.adcrops.sdk.util.AdcEncryptor', u'net.gree.asdk.core.codec.AesEnc', u'net.gree.asdk.core.storage.CookieStorage', u'net.gree.asdk.core.util.Util', u'net.lingala.zip4j.crypto.AESDecrypter', u'net.lingala.zip4j.crypto.AESEncrpyter', u'net.lingala.zip4j.crypto.IDecrypter', u'net.lingala.zip4j.crypto.IEncrypter', u'net.lingala.zip4j.crypto.StandardDecrypter', u'net.lingala.zip4j.crypto.StandardEncrypter', u'net.lingala.zip4j.crypto.engine.AESEngine', u'net.lingala.zip4j.crypto.engine.ZipCryptoEngine', u'net.lingala.zip4j.exception.ZipException', u'net.lingala.zip4j.io.CipherOutputStream', u'net.metaps.util.Encode', u'o', u'oicq.wlogin_sdk.push.request_push', u'oicq.wlogin_sdk.register.reg_request_get_account', u'oicq.wlogin_sdk.register.reg_request_query_msg_status', u'oicq.wlogin_sdk.register.reg_request_submit_msg_chk', u'oicq.wlogin_sdk.request.oicq_request', u'oicq.wlogin_sdk.request.request_TGTGT', u'oicq.wlogin_sdk.request.request_app_signature', u'oicq.wlogin_sdk.request.request_change_sig', u'oicq.wlogin_sdk.request.request_check_apkmd5', u'oicq.wlogin_sdk.request.request_check_sms', u'oicq.wlogin_sdk.request.request_checkimage', u'oicq.wlogin_sdk.request.request_delay', u'oicq.wlogin_sdk.request.request_fast_login', u'oicq.wlogin_sdk.request.request_flush_sms', u'oicq.wlogin_sdk.request.request_flushimage', u'oicq.wlogin_sdk.request.request_getuin', u'oicq.wlogin_sdk.request.request_ping', u'oicq.wlogin_sdk.request.request_report_error', u'oicq.wlogin_sdk.request.request_transport', u'oicq.wlogin_sdk.tools.CryptorImpl', u'oicq.wlogin_sdk.tools.cryptor', u'oicq.wlogin_sdk.tools.util', u'oracle.net.ano.CryptoDataPacket', u'org.a.a.a.a.i', u'org.agoo.ut.UT$Adv', u'org.apache.http.ConnectionClosedException', u'org.apache.http.Header', u'org.apache.http.HeaderElement', u'org.apache.http.HeaderElementIterator', u'org.apache.http.HeaderIterator', u'org.apache.http.HttpConnection', u'org.apache.http.HttpConnectionMetrics', u'org.apache.http.HttpEntity', u'org.apache.http.HttpEntityEnclosingRequest', u'org.apache.http.HttpException', u'org.apache.http.HttpHost', u'org.apache.http.HttpMessage', u'org.apache.http.HttpRequest', u'org.apache.http.HttpResponse', u'org.apache.http.HttpServerConnection', u'org.apache.http.HttpVersion', u'org.apache.http.MalformedChunkCodingException', u'org.apache.http.MethodNotSupportedException', u'org.apache.http.NameValuePair', u'org.apache.http.ParseException', u'org.apache.http.ProtocolException', u'org.apache.http.ProtocolVersion', u'org.apache.http.RequestLine', u'org.apache.http.StatusLine', u'org.apache.http.TokenIterator', u'org.apache.http.auth.AuthScope', u'org.apache.http.auth.AuthState', u'org.apache.http.auth.InvalidCredentialsException', u'org.apache.http.auth.NTCredentials', u'org.apache.http.auth.UsernamePasswordCredentials', u'org.apache.http.auth.params.AuthParams', u'org.apache.http.client.CircularRedirectException', u'org.apache.http.client.ClientProtocolException', u'org.apache.http.client.CookieStore', u'org.apache.http.client.CredentialsProvider', u'org.apache.http.client.HttpClient', u'org.apache.http.client.HttpRequestRetryHandler', u'org.apache.http.client.HttpResponseException', u'org.apache.http.client.ResponseHandler', u'org.apache.http.client.entity.UrlEncodedFormEntity', u'org.apache.http.client.methods.AbortableHttpRequest', u'org.apache.http.client.methods.HttpDelete', u'org.apache.http.client.methods.HttpEntityEnclosingRequestBase', u'org.apache.http.client.methods.HttpGet', u'org.apache.http.client.methods.HttpHead', u'org.apache.http.client.methods.HttpOptions', u'org.apache.http.client.methods.HttpPatch', u'org.apache.http.client.methods.HttpPost', u'org.apache.http.client.methods.HttpPut', u'org.apache.http.client.methods.HttpRequestBase', u'org.apache.http.client.methods.HttpTrace', u'org.apache.http.client.methods.HttpUriRequest', u'org.apache.http.client.params.HttpClientParams', u'org.apache.http.client.protocol.ResponseProcessCookies', u'org.apache.http.client.utils.CloneUtils', u'org.apache.http.client.utils.URIUtils', u'org.apache.http.client.utils.URLEncodedUtils', u'org.apache.http.conn.ClientConnectionManager', u'org.apache.http.conn.ClientConnectionManagerFactory', u'org.apache.http.conn.ConnectTimeoutException', u'org.apache.http.conn.ConnectionPoolTimeoutException', u'org.apache.http.conn.ConnectionReleaseTrigger', u'org.apache.http.conn.params.ConnManagerParams', u'org.apache.http.conn.params.ConnPerRouteBean', u'org.apache.http.conn.params.ConnRouteParams', u'org.apache.http.conn.routing.HttpRoute', u'org.apache.http.conn.routing.HttpRoutePlanner', u'org.apache.http.conn.scheme.HostNameResolver', u'org.apache.http.conn.scheme.PlainSocketFactory', u'org.apache.http.conn.scheme.Scheme', u'org.apache.http.conn.scheme.SchemeRegistry', u'org.apache.http.conn.scheme.SocketFactory', u'org.apache.http.conn.ssl.AbstractVerifier', u'org.apache.http.conn.ssl.AllowAllHostnameVerifier', u'org.apache.http.conn.ssl.SSLSocketFactory', u'org.apache.http.conn.ssl.StrictHostnameVerifier', u'org.apache.http.conn.ssl.X509HostnameVerifier', u'org.apache.http.conn.util.InetAddressUtils', u'org.apache.http.cookie.Cookie', u'org.apache.http.entity.AbstractHttpEntity', u'org.apache.http.entity.BasicHttpEntity', u'org.apache.http.entity.BufferedHttpEntity', u'org.apache.http.entity.ByteArrayEntity', u'org.apache.http.entity.EntityTemplate', u'org.apache.http.entity.FileEntity', u'org.apache.http.entity.HttpEntityWrapper', u'org.apache.http.entity.InputStreamEntity', u'org.apache.http.entity.StringEntity', u'org.apache.http.entity.mime.MultipartEntity', u'org.apache.http.entity.mime.MultipartEntityBuilder', u'org.apache.http.entity.mime.a.b', u'org.apache.http.entity.mime.a.e', u'org.apache.http.entity.mime.a.g', u'org.apache.http.entity.mime.content.AbstractContentBody', u'org.apache.http.entity.mime.content.ByteArrayBody', u'org.apache.http.entity.mime.content.FileBody', u'org.apache.http.entity.mime.content.InputStreamBody', u'org.apache.http.entity.mime.content.StringBody', u'org.apache.http.entity.mime.f', u'org.apache.http.impl.AbstractHttpServerConnection', u'org.apache.http.impl.DefaultConnectionReuseStrategy', u'org.apache.http.impl.DefaultHttpClientConnection', u'org.apache.http.impl.DefaultHttpRequestFactory', u'org.apache.http.impl.DefaultHttpResponseFactory', u'org.apache.http.impl.DefaultHttpServerConnection', u'org.apache.http.impl.NoConnectionReuseStrategy', u'org.apache.http.impl.auth.BasicScheme', u'org.apache.http.impl.auth.UnsupportedDigestAlgorithmException', u'org.apache.http.impl.client.AbstractHttpClient', u'org.apache.http.impl.client.BasicCookieStore', u'org.apache.http.impl.client.BasicCredentialsProvider', u'org.apache.http.impl.client.BasicResponseHandler', u'org.apache.http.impl.client.ClientParamsStack', u'org.apache.http.impl.client.DefaultConnectionKeepAliveStrategy', u'org.apache.http.impl.client.DefaultHttpClient', u'org.apache.http.impl.client.DefaultHttpRequestRetryHandler', u'org.apache.http.impl.client.DefaultRedirectHandler', u'org.apache.http.impl.client.EntityEnclosingRequestWrapper', u'org.apache.http.impl.client.RedirectLocations', u'org.apache.http.impl.client.RequestWrapper', u'org.apache.http.impl.conn.ProxySelectorRoutePlanner', u'org.apache.http.impl.conn.SingleClientConnManager', u'org.apache.http.impl.conn.tsccm.ThreadSafeClientConnManager', u'org.apache.http.impl.cookie.BasicClientCookie', u'org.apache.http.impl.cookie.DateUtils', u'org.apache.http.io.SessionInputBuffer', u'org.apache.http.message.AbstractHttpMessage', u'org.apache.http.message.BasicHeader', u'org.apache.http.message.BasicHeaderElementIterator', u'org.apache.http.message.BasicHeaderValueParser', u'org.apache.http.message.BasicHttpEntityEnclosingRequest', u'org.apache.http.message.BasicHttpRequest', u'org.apache.http.message.BasicHttpResponse', u'org.apache.http.message.BasicLineParser', u'org.apache.http.message.BasicListHeaderIterator', u'org.apache.http.message.BasicNameValuePair', u'org.apache.http.message.BasicRequestLine', u'org.apache.http.message.BasicStatusLine', u'org.apache.http.message.BufferedHeader', u'org.apache.http.message.ParserCursor', u'org.apache.http.params.AbstractHttpParams', u'org.apache.http.params.BasicHttpParams', u'org.apache.http.params.DefaultedHttpParams', u'org.apache.http.params.HttpConnectionParams', u'org.apache.http.params.HttpParams', u'org.apache.http.params.HttpProtocolParams', u'org.apache.http.protocol.BasicHttpContext', u'org.apache.http.protocol.BasicHttpProcessor', u'org.apache.http.protocol.HTTP', u'org.apache.http.protocol.HttpContext', u'org.apache.http.protocol.HttpRequestHandlerRegistry', u'org.apache.http.protocol.HttpService', u'org.apache.http.protocol.ResponseConnControl', u'org.apache.http.protocol.ResponseContent', u'org.apache.http.protocol.ResponseDate', u'org.apache.http.protocol.ResponseServer', u'org.apache.http.protocol.SyncBasicHttpContext', u'org.apache.http.util.ByteArrayBuffer', u'org.apache.http.util.CharArrayBuffer', u'org.apache.http.util.EncodingUtils', u'org.apache.http.util.EntityUtils', u'org.apache.http.util.LangUtils', u'org.apache.thrift.TException', u'org.apache.thrift.meta_data.FieldMetaData', u'org.apache.thrift.protocol.TField', u'org.bouncycastle.crypto.DataLengthException', u'org.bouncycastle.crypto.engines.AESEngine', u'org.bouncycastle.crypto.engines.AESFastEngine', u'org.bouncycastle.crypto.engines.AESLightEngine', u'org.bouncycastle.crypto.engines.BlowfishEngine', u'org.bouncycastle.crypto.engines.CAST5Engine', u'org.bouncycastle.crypto.engines.IESEngine', u'org.bouncycastle.crypto.engines.NaccacheSternEngine', u'org.bouncycastle.crypto.engines.NoekeonEngine', u'org.bouncycastle.crypto.engines.RC2Engine', u'org.bouncycastle.crypto.engines.RC532Engine', u'org.bouncycastle.crypto.engines.RC564Engine', u'org.bouncycastle.crypto.engines.RC6Engine', u'org.bouncycastle.crypto.engines.RijndaelEngine', u'org.bouncycastle.crypto.engines.SerpentEngine', u'org.bouncycastle.crypto.engines.Shacal2Engine', u'org.bouncycastle.crypto.engines.SkipjackEngine', u'org.bouncycastle.crypto.engines.TEAEngine', u'org.bouncycastle.crypto.engines.ThreefishEngine$ThreefishCipher', u'org.bouncycastle.crypto.engines.TwofishEngine', u'org.bouncycastle.crypto.engines.XTEAEngine', u'org.bouncycastle.crypto.kems.ECIESKeyEncapsulation', u'org.bouncycastle.crypto.kems.RSAKeyEncapsulation', u'org.bouncycastle.crypto.modes.CBCBlockCipher', u'org.bouncycastle.crypto.modes.CFBBlockCipher', u'org.bouncycastle.crypto.modes.OpenPGPCFBBlockCipher', u'org.bouncycastle.crypto.modes.PGPCFBBlockCipher', u'org.bouncycastle.crypto.tls.TlsEncryptionCredentials', u'org.bouncycastle.pqc.crypto.mceliece.McElieceCCA2Primitives', u'org.bouncycastle.pqc.jcajce.provider.util.AsymmetricHybridCipher', u'org.coursera.courkit.Encryptor', u'org.jaudiotagger.audio.mp4.atom.Mp4FtypBox$Brand', u'org.jaudiotagger.logging.AbstractTagDisplayFormatter', u'org.jaudiotagger.logging.ErrorMessage', u'org.jivesoftware.smack.XMPPException', u'org.json.JSONObject', u'org.kontalk.client.Protocol$MessagePostRequest$Builder', u'org.kontalk.crypto.Coder', u'org.kontalk.message.AbstractMessage', u'org.kontalk.ui.MessagingPreferences', u'org.teleal.cling.model.types.ErrorCode', u'pl.solidexplorer.bookmarks.j', u'pl.solidexplorer.c.n', u'safiap.framework.c.b', u'safiap.framework.util.MyLogger', u'soja.base.SojaEncrypt', u'soja.security.DES', u'tv.ouya.console.api.OuyaEncryptionHelper', u'unrar.pack.out.ph.BaseCipher', u'unrar.pack.out.ph.Rijndael', u'xcxin.fehd.util.DES']
