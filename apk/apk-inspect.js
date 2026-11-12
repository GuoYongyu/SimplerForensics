/*
 * APK 静态检查编排：把 ZIP、Manifest、资源表、签名、DEX 与 assets 汇总成
 * 一份供页面和 JSON 报告使用的只读结果。所有解析都在本机进行。
 */
(() => {
  'use strict';

  const root = typeof globalThis !== 'undefined' ? globalThis : window;
  const Api = root.ApkInspect = root.ApkInspect || {};
  const U = Api.util;
  const ANDROID = Api.ANDROID_NS;

  const LIMITS = {
    assets: 1200,
    assetScanBytes: 256 * 1024,
    assetHashBytes: 4 * 1024 * 1024,
    dexBytes: 24 * 1024 * 1024,
    dexTotalBytes: 96 * 1024 * 1024,
    dexStrings: 120000,
    urls: 400,
    secrets: 200,
    resourceStrings: 4000,
    components: 400,
    rawXmlBytes: 512 * 1024
  };

  const SECRET_RULES = [
    { id: 'flag', label: 'Flag 形式字符串', pattern: /\b(?:flag|ctf)\{[^}\r\n]{1,200}\}/gi },
    { id: 'private-key', label: '私钥 PEM 头', pattern: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----/g },
    { id: 'aws-key', label: 'AWS Access Key', pattern: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g },
    { id: 'google-api-key', label: 'Google API Key', pattern: /\bAIza[0-9A-Za-z_-]{35}\b/g },
    { id: 'jwt', label: 'JWT 令牌', pattern: /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g },
    { id: 'aliyun-key', label: '阿里云 AccessKey', pattern: /\bLTAI[0-9A-Za-z]{12,24}\b/g },
    { id: 'tencent-key', label: '腾讯云 SecretId', pattern: /\bAKID[0-9A-Za-z]{13,40}\b/g },
    { id: 'github-token', label: 'GitHub Token', pattern: /\bgh[pousr]_[A-Za-z0-9]{36,}\b|\bgithub_pat_[A-Za-z0-9_]{40,}\b/g },
    { id: 'slack-token', label: 'Slack Token', pattern: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g },
    { id: 'firebase', label: 'Firebase 数据库地址', pattern: /https?:\/\/[a-z0-9-]+\.(?:firebaseio\.com|firebasedatabase\.app)/gi },
    { id: 'db-uri', label: '数据库连接串', pattern: /\b(?:jdbc:[a-z0-9]+:\/\/|mysql:\/\/|postgres(?:ql)?:\/\/|mongodb(?:\+srv)?:\/\/)[^\s"'<>]{4,200}/gi },
    { id: 'password', label: '疑似口令赋值', pattern: /\b(?:password|passwd|pwd|pass)\s*[=:]\s*["']?[^\s"'<>,;]{3,80}/gi },
    { id: 'api-secret', label: '疑似密钥/令牌赋值', pattern: /\b(?:api[_-]?key|apikey|secret|client[_-]?secret|access[_-]?token|auth[_-]?token|app[_-]?secret)\b\s*[=:]\s*["'][^"']{6,120}["']/gi }
  ];
  const URL_PATTERN = /https?:\/\/[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+/gi;
  const EMAIL_PATTERN = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,24}\b/g;
  const IPV4_PATTERN = /\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b/g;
  const STORAGE_PATH_PATTERN = /\/(?:data\/data|data\/user\/\d+|storage\/emulated\/\d+|sdcard)\/[A-Za-z0-9._\-\/]{2,160}/g;

  /* ------------------------------------------------------------------ */
  /* Manifest 读取辅助                                                    */
  /* ------------------------------------------------------------------ */

  function attr(element, name, ns = ANDROID) {
    if (!element) return null;
    return element.attrs.find(item => item.name === name && item.ns === ns) || null;
  }
  function rawAttr(element, name) {
    if (!element) return null;
    return element.attrs.find(item => item.name === name);
  }
  function resolveValue(attribute, table) {
    if (!attribute) return null;
    if (attribute.reference && table) {
      const resource = Api.arsc.resolveResource(table, attribute.reference);
      if (resource && typeof resource.value === 'string') {
        return { text: resource.value, reference: '0x' + attribute.reference.toString(16), config: resource.config.label };
      }
    }
    if (attribute.reference) return { text: attribute.value, reference: '0x' + attribute.reference.toString(16), unresolved: true };
    return { text: attribute.value };
  }
  function textOf(element, name, table, ns) {
    const value = resolveValue(attr(element, name, ns), table);
    return value ? value.text : null;
  }
  function boolOf(element, name) {
    const attribute = attr(element, name);
    if (!attribute) return null;
    if (attribute.type === 0x12) return attribute.data !== 0;
    if (attribute.value === 'true') return true;
    if (attribute.value === 'false') return false;
    return null;
  }
  function intOf(element, name) {
    const attribute = attr(element, name);
    if (!attribute) return null;
    if (attribute.type === 0x10 || attribute.type === 0x11) return attribute.data | 0;
    const value = Number(attribute.value);
    return Number.isFinite(value) ? value : null;
  }
  function qualify(name, packageName) {
    if (!name) return '';
    if (name.startsWith('.')) return packageName + name;
    if (!name.includes('.')) return packageName + '.' + name;
    return name;
  }

  const PROTECTION_BASE = { 0: 'normal', 1: 'dangerous', 2: 'signature', 3: 'signature|privileged（signatureOrSystem）' };
  const PROTECTION_FLAGS = {
    0x4: 'privileged', 0x10: 'system', 0x20: 'development', 0x40: 'appop', 0x80: 'pre23',
    0x100: 'installer', 0x200: 'verifier', 0x400: 'preinstalled', 0x800: 'setup', 0x1000: 'instant',
    0x2000: 'runtime', 0x4000: 'oem', 0x8000: 'vendorPrivileged', 0x10000: 'textClassifier',
    0x20000: 'configurator', 0x40000: 'incidentReportApprover', 0x80000: 'appPredictor', 0x100000: 'module'
  };
  function decodeProtectionLevel(value) {
    if (value === null || value === undefined) return null;
    const numeric = typeof value === 'number' ? value : Number(value);
    if (!Number.isFinite(numeric)) return { text: String(value) };
    const base = numeric & 0xf;
    const flags = Object.entries(PROTECTION_FLAGS).filter(([bit]) => numeric & Number(bit)).map(([, name]) => name);
    return {
      value: numeric,
      base: PROTECTION_BASE[base] || ('0x' + base.toString(16)),
      flags,
      text: (PROTECTION_BASE[base] || '0x' + base.toString(16)) + (flags.length ? ' · ' + flags.join(' · ') : '')
    };
  }
  const LAUNCH_MODES = ['standard', 'singleTop', 'singleTask', 'singleInstance', 'singleInstancePerTask'];
  const ORIENTATIONS = {
    0: 'unspecified', 1: 'portrait', 2: 'landscape', 3: 'user', 4: 'behind', 5: 'sensor',
    6: 'nosensor', 7: 'sensorLandscape', 8: 'sensorPortrait', 9: 'reverseLandscape', 10: 'reversePortrait',
    11: 'fullSensor', 12: 'userLandscape', 13: 'userPortrait', 14: 'fullUser', 15: 'locked'
  };

  function parseIntentFilter(element) {
    const filter = { actions: [], categories: [], data: [], priority: intOf(element, 'priority'), autoVerify: boolOf(element, 'autoVerify') };
    for (const child of element.children) {
      if (child.name === 'action') {
        const name = textOf(child, 'name');
        if (name) filter.actions.push(name);
      } else if (child.name === 'category') {
        const name = textOf(child, 'name');
        if (name) filter.categories.push(name);
      } else if (child.name === 'data') {
        const entry = {};
        for (const key of ['scheme', 'host', 'port', 'path', 'pathPrefix', 'pathPattern', 'pathAdvancedPattern', 'ssp', 'sspPrefix', 'sspPattern', 'mimeType']) {
          const value = textOf(child, key);
          if (value) entry[key] = value;
        }
        if (Object.keys(entry).length) filter.data.push(entry);
      }
    }
    return filter;
  }

  function normalizeComponent(element, type, packageName, table, targetSdk) {
    const name = qualify(textOf(element, 'name'), packageName);
    const intentFilters = element.children.filter(child => child.name === 'intent-filter').map(parseIntentFilter);
    const declaredExported = boolOf(element, 'exported');
    const hasFilter = intentFilters.length > 0;
    const provider = type === 'provider';
    let effective;
    let exportReason;
    if (declaredExported !== null) {
      effective = declaredExported;
      exportReason = 'AndroidManifest 显式声明';
    } else if (provider) {
      const legacyDefault = targetSdk !== null && targetSdk < 17;
      effective = legacyDefault;
      exportReason = legacyDefault
        ? '未声明；targetSdk < 17，Provider 默认导出'
        : '未声明；Android 4.2（API 17）起默认不导出';
    } else {
      effective = hasFilter;
      exportReason = hasFilter ? '未声明；因含 intent-filter 默认导出' : '未声明；默认不导出';
    }
    const permission = textOf(element, 'permission');
    const component = {
      type,
      name,
      shortName: name.startsWith(packageName + '.') ? name.slice(packageName.length + 1) : name,
      exported: effective,
      exportedDeclared: declaredExported,
      exportReason,
      hasIntentFilter: hasFilter,
      enabled: boolOf(element, 'enabled'),
      permission,
      readPermission: textOf(element, 'readPermission'),
      writePermission: textOf(element, 'writePermission'),
      directBootAware: boolOf(element, 'directBootAware'),
      process: textOf(element, 'process'),
      label: textOf(element, 'label', table),
      launchMode: type === 'activity' || type === 'activity-alias' ? LAUNCH_MODES[intOf(element, 'launchMode') ?? 0] || null : null,
      taskAffinity: textOf(element, 'taskAffinity'),
      screenOrientation: type === 'activity' || type === 'activity-alias' ? (ORIENTATIONS[intOf(element, 'screenOrientation') ?? 0] || null) : null,
      targetActivity: type === 'activity-alias' ? qualify(textOf(element, 'targetActivity'), packageName) : null,
      authorities: provider ? textOf(element, 'authorities') : null,
      grantUriPermissions: provider ? boolOf(element, 'grantUriPermissions') : null,
      syncable: provider ? boolOf(element, 'syncable') : null,
      initOrder: provider ? intOf(element, 'initOrder') : null,
      intentFilters
    };
    component.launcher = intentFilters.some(filter =>
      filter.actions.includes('android.intent.action.MAIN') &&
      (filter.categories.includes('android.intent.category.LAUNCHER') || filter.categories.includes('android.intent.category.LEANBACK_LAUNCHER')));
    component.risk = effective
      ? (permission || component.readPermission ? 'exported-with-permission' : 'exported-no-permission')
      : 'not-exported';
    if (hasFilter && declaredExported === null && targetSdk !== null && targetSdk >= 31 && type !== 'provider') {
      component.targetSdk31Note = 'Android 12（API 31）及以上要求含 intent-filter 的组件显式声明 android:exported。';
    }
    return component;
  }

  function normalizeManifest(document, table, context) {
    const rootElement = document.root;
    if (!rootElement || rootElement.name !== 'manifest') throw new Error('AndroidManifest.xml 根元素不是 <manifest>。');
    const packageName = rawAttr(rootElement, 'package')?.value || '';
    const minSdk = intOf(rootElement.children.find(child => child.name === 'uses-sdk') || null, 'minSdkVersion');
    const targetSdk = intOf(rootElement.children.find(child => child.name === 'uses-sdk') || null, 'targetSdkVersion');
    const appElement = rootElement.children.find(child => child.name === 'application') || null;
    const sdkElement = rootElement.children.find(child => child.name === 'uses-sdk') || null;
    const appLabel = resolveValue(attr(appElement, 'label'), table);
    const appIcon = resolveValue(attr(appElement, 'icon'), table);
    const manifest = {
      package: packageName,
      versionName: textOf(rootElement, 'versionName'),
      versionCode: intOf(rootElement, 'versionCode'),
      versionCodeMajor: intOf(rootElement, 'versionCodeMajor'),
      compileSdkVersion: intOf(rootElement, 'compileSdkVersion'),
      compileSdkVersionCodename: textOf(rootElement, 'compileSdkVersionCodename'),
      platformBuildVersionCode: intOf(rootElement, 'platformBuildVersionCode'),
      platformBuildVersionName: textOf(rootElement, 'platformBuildVersionName'),
      installLocation: intOf(rootElement, 'installLocation'),
      split: textOf(rootElement, 'split'),
      configForSplit: textOf(rootElement, 'configForSplit'),
      isFeatureSplit: boolOf(rootElement, 'isFeatureSplit'),
      isSplitRequired: boolOf(rootElement, 'isSplitRequired'),
      isolatedSplits: boolOf(rootElement, 'isolatedSplits'),
      requiredSplitTypes: textOf(rootElement, 'requiredSplitTypes'),
      splitTypes: textOf(rootElement, 'splitTypes'),
      targetSandboxVersion: intOf(rootElement, 'targetSandboxVersion'),
      sharedUserId: textOf(rootElement, 'sharedUserId'),
      sharedUserLabel: resolveValue(attr(rootElement, 'sharedUserLabel'), table),
      minSdk,
      targetSdk,
      maxSdk: intOf(sdkElement, 'maxSdkVersion'),
      sdkExtensions: null,
      appLabel,
      appIcon,
      application: null,
      activities: [],
      activityAliases: [],
      services: [],
      receivers: [],
      providers: [],
      usesPermissions: [],
      declaredPermissions: [],
      permissionGroups: [],
      features: [],
      libraries: [],
      nativeLibraries: [],
      queries: [],
      metaData: [],
      instrumentations: [],
      supportsScreens: null,
      supportsGlTextures: [],
      usesConfiguration: null,
      rawXml: ''
    };

    if (sdkElement) {
      const extensionChildren = sdkElement.children.filter(child => child.name === 'extension');
      if (extensionChildren.length) {
        manifest.sdkExtensions = extensionChildren.map(child => ({
          sdk: intOf(child, 'sdkVersion'),
          minExtension: intOf(child, 'minExtensionVersion')
        }));
      }
    }

    if (appElement) {
      const booleanFields = [
        'debuggable', 'allowBackup', 'usesCleartextTraffic', 'extractNativeLibs', 'requestLegacyExternalStorage',
        'preserveLegacyExternalStorage', 'testOnly', 'hardwareAccelerated', 'largeHeap', 'persistent', 'enabled',
        'allowTaskReparenting', 'vmSafeMode', 'directBootAware', 'defaultToDeviceProtectedStorage', 'hasCode',
        'killAfterRestore', 'restoreAnyVersion', 'supportsRtl', 'resizeableActivity', 'supportsPictureInPicture',
        'allowAudioPlaybackCapture', 'enableOnBackInvokedCallback', 'allowNativeHeapPointerTagging', 'usesNonSdkApi',
        'requestRawExternalStorageAccess', 'gwpAsanEnabled', 'memtagMode'
      ];
      const textFields = [
        'name', 'theme', 'description', 'appComponentFactory', 'backupAgent', 'manageSpaceActivity',
        'networkSecurityConfig', 'dataExtractionRules', 'fullBackupContent', 'classLoader', 'localeConfig',
        'zygotePreloadName', 'banner', 'logo', 'icon', 'roundIcon', 'label', 'process'
      ];
      const application = { attributes: {} };
      for (const field of booleanFields) application[field] = boolOf(appElement, field);
      for (const field of textFields) {
        if (field === 'name') application.className = textOf(appElement, field) ? qualify(textOf(appElement, field), packageName) : null;
        else if (field === 'label' || field === 'icon') continue;
        else application[field] = textOf(appElement, field, table);
      }
      application.usesNonSdkApi = boolOf(appElement, 'usesNonSdkApi');
      application.maxAspectRatio = textOf(appElement, 'maxAspectRatio');
      application.minAspectRatio = textOf(appElement, 'minAspectRatio');
      application.memtagMode = textOf(appElement, 'memtagMode');
      const known = new Set([
        ...booleanFields, ...textFields, 'usesNonSdkApi', 'maxAspectRatio', 'minAspectRatio', 'memtagMode',
        'appCategory', 'requestLegacyExternalStorage'
      ]);
      for (const attribute of appElement.attrs) {
        const key = (attribute.ns ? (attribute.prefix || 'android') + ':' : '') + attribute.name;
        if (known.has(attribute.name)) continue;
        application.attributes[key] = attribute.value;
      }
      manifest.application = application;
      for (const child of appElement.children) {
        if (child.name === 'activity' || child.name === 'activity-alias') {
          const component = normalizeComponent(child, child.name === 'activity-alias' ? 'activity-alias' : 'activity', packageName, table, targetSdk);
          if (child.name === 'activity-alias') manifest.activityAliases.push(component);
          else manifest.activities.push(component);
        } else if (child.name === 'service') {
          manifest.services.push(normalizeComponent(child, 'service', packageName, table, targetSdk));
        } else if (child.name === 'receiver') {
          manifest.receivers.push(normalizeComponent(child, 'receiver', packageName, table, targetSdk));
        } else if (child.name === 'provider') {
          manifest.providers.push(normalizeComponent(child, 'provider', packageName, table, targetSdk));
        } else if (child.name === 'meta-data') {
          manifest.metaData.push(metaDataEntry(child, table));
        } else if (child.name === 'uses-library') {
          manifest.libraries.push({ name: textOf(child, 'name'), required: boolOf(child, 'required'), version: textOf(child, 'version') });
        } else if (child.name === 'uses-native-library') {
          manifest.nativeLibraries.push({ name: textOf(child, 'name'), required: boolOf(child, 'required') });
        } else if (child.name === 'activity-alias') {
          // 已在上方处理。
        }
      }
    }

    for (const child of rootElement.children) {
      if (child.name === 'uses-permission' || child.name === 'uses-permission-sdk-23' || child.name === 'uses-permission-sdk-m') {
        manifest.usesPermissions.push({
          name: textOf(child, 'name'),
          maxSdkVersion: intOf(child, 'maxSdkVersion'),
          sdk23: child.name === 'uses-permission-sdk-23',
          sdkM: child.name === 'uses-permission-sdk-m'
        });
      } else if (child.name === 'permission') {
        const level = decodeProtectionLevel(attr(child, 'protectionLevel')?.value);
        manifest.declaredPermissions.push({
          name: textOf(child, 'name'),
          label: textOf(child, 'label', table),
          description: textOf(child, 'description', table),
          protectionLevel: level,
          permissionGroup: textOf(child, 'permissionGroup'),
          backgroundPermission: textOf(child, 'backgroundPermission')
        });
      } else if (child.name === 'permission-group' || child.name === 'permission-tree') {
        manifest.permissionGroups.push({
          type: child.name,
          name: textOf(child, 'name'),
          label: textOf(child, 'label', table),
          description: textOf(child, 'description', table),
          icon: textOf(child, 'icon')
        });
      } else if (child.name === 'uses-feature') {
        const glEs = attr(child, 'glEsVersion');
        manifest.features.push({
          name: textOf(child, 'name'),
          required: boolOf(child, 'required'),
          version: textOf(child, 'version'),
          glEsVersion: glEs ? formatGlEs(glEs.data) : null
        });
      } else if (child.name === 'uses-library') {
        manifest.libraries.push({ name: textOf(child, 'name'), required: boolOf(child, 'required'), version: textOf(child, 'version') });
      } else if (child.name === 'uses-native-library') {
        manifest.nativeLibraries.push({ name: textOf(child, 'name'), required: boolOf(child, 'required') });
      } else if (child.name === 'meta-data') {
        manifest.metaData.push(metaDataEntry(child, table));
      } else if (child.name === 'queries') {
        manifest.queries = parseQueries(child);
      } else if (child.name === 'instrumentation') {
        manifest.instrumentations.push({
          name: qualify(textOf(child, 'name'), packageName),
          targetPackage: textOf(child, 'targetPackage'),
          functionalTest: boolOf(child, 'functionalTest'),
          handleProfiling: boolOf(child, 'handleProfiling')
        });
      } else if (child.name === 'supports-screens') {
        manifest.supportsScreens = {};
        for (const field of ['anyDensity', 'smallScreens', 'normalScreens', 'largeScreens', 'xlargeScreens', 'resizeable', 'requiresSmallestWidthDp', 'compatibleWidthLimitDp', 'largestWidthLimitDp']) {
          const attribute = attr(child, field);
          if (attribute) manifest.supportsScreens[field] = field.endsWith('Dp') ? attribute.value : boolOf(child, field);
        }
      } else if (child.name === 'supports-gl-texture') {
        const name = textOf(child, 'name');
        if (name) manifest.supportsGlTextures.push(name);
      } else if (child.name === 'uses-configuration') {
        manifest.usesConfiguration = {};
        for (const attribute of child.attrs) manifest.usesConfiguration[attribute.name] = attribute.value;
      } else if (child.name === 'uses-split') {
        const name = textOf(child, 'name');
        if (name) manifest.splitTypes = (manifest.splitTypes || '') + (manifest.splitTypes ? ', ' : '') + name;
      }
    }

    manifest.launchers = [...manifest.activities, ...manifest.activityAliases].filter(component => component.launcher).map(component => component.name);
    manifest.componentCount = {
      activities: manifest.activities.length,
      activityAliases: manifest.activityAliases.length,
      services: manifest.services.length,
      receivers: manifest.receivers.length,
      providers: manifest.providers.length
    };
    manifest.rawXml = Api.axml.serialize(document);
    return manifest;
  }
  function formatGlEs(data) {
    if (typeof data !== 'number') return null;
    return ((data >> 16) & 0xffff) + '.' + (data & 0xffff);
  }
  function metaDataEntry(element, table) {
    const value = resolveValue(attr(element, 'value'), table);
    const resourceAttribute = attr(element, 'resource');
    const resource = resolveValue(resourceAttribute, table);
    return {
      name: textOf(element, 'name'),
      value: value ? value.text : null,
      valueReference: value?.reference || null,
      resource: resource ? resource.text : null,
      resourceReference: resource?.reference || null
    };
  }
  function parseQueries(element) {
    const packages = [], providers = [], intents = [];
    for (const child of element.children) {
      if (child.name === 'package') packages.push(textOf(child, 'name'));
      else if (child.name === 'provider') providers.push(textOf(child, 'authorities'));
      else if (child.name === 'intent') {
        const actions = child.children.filter(item => item.name === 'action').map(item => textOf(item, 'name')).filter(Boolean);
        if (actions.length) intents.push(actions);
      }
    }
    return { packages, providers, intents };
  }

  /* ------------------------------------------------------------------ */
  /* 文本线索扫描                                                         */
  /* ------------------------------------------------------------------ */

  function scanText(text, source, state) {
    if (!text) return;
    const compact = text.replace(/\r/g, '');
    let match;
    URL_PATTERN.lastIndex = 0;
    while ((match = URL_PATTERN.exec(compact)) && state.urls.length < LIMITS.urls) {
      const url = match[0].replace(/[.,;:)\]}'"]+$/, '');
      if (url.length < 10 || state.urlSeen.has(url)) continue;
      state.urlSeen.add(url);
      state.urls.push({ value: url, source });
    }
    EMAIL_PATTERN.lastIndex = 0;
    while ((match = EMAIL_PATTERN.exec(compact)) && state.emails.length < 120) {
      if (!state.emailSeen.has(match[0])) { state.emailSeen.add(match[0]); state.emails.push({ value: match[0], source }); }
    }
    IPV4_PATTERN.lastIndex = 0;
    while ((match = IPV4_PATTERN.exec(compact)) && state.ips.length < 160) {
      const value = match[0];
      if (value === '0.0.0.0' || value === '127.0.0.1' || state.ipSeen.has(value)) continue;
      state.ipSeen.add(value);
      state.ips.push({ value, private: isPrivateIp(value), source });
    }
    STORAGE_PATH_PATTERN.lastIndex = 0;
    while ((match = STORAGE_PATH_PATTERN.exec(compact)) && state.paths.length < 160) {
      const value = match[0].replace(/[.,;:'")\]}]+$/, '');
      if (value.length < 8 || state.pathSeen.has(value)) continue;
      state.pathSeen.add(value);
      state.paths.push({ value, source });
    }
    for (const rule of SECRET_RULES) {
      if (state.secrets.length >= LIMITS.secrets) break;
      rule.pattern.lastIndex = 0;
      while ((match = rule.pattern.exec(compact))) {
        const value = match[0].trim();
        if (!value || value.length < 4) continue;
        const key = rule.id + '\u0000' + value;
        if (state.secretSeen.has(key)) continue;
        state.secretSeen.add(key);
        state.secrets.push({ kind: rule.id, label: rule.label, value: value.slice(0, 240), source });
        if (state.secrets.length >= LIMITS.secrets) break;
      }
    }
  }
  function isPrivateIp(value) {
    const [a, b] = value.split('.').map(Number);
    return a === 10 || a === 127 || (a === 192 && b === 168) || (a === 172 && b >= 16 && b <= 31) || a === 0;
  }

  /* ------------------------------------------------------------------ */
  /* DEX                                                                  */
  /* ------------------------------------------------------------------ */

  function readDexHeader(bytes) {
    if (bytes.length < 112) throw new Error('DEX 文件头长度不足。');
    if (String.fromCharCode(bytes[0], bytes[1], bytes[2], bytes[3]) !== 'dex\n') throw new Error('DEX 文件头无效。');
    const version = String.fromCharCode(bytes[4], bytes[5], bytes[6]);
    return {
      version,
      checksum: U.readU32(bytes, 8),
      signature: U.hex(bytes.subarray(12, 32)),
      fileSize: U.readU32(bytes, 32),
      headerSize: U.readU32(bytes, 36),
      endianTag: U.readU32(bytes, 40),
      stringIdsSize: U.readU32(bytes, 56),
      stringIdsOff: U.readU32(bytes, 60),
      typeIdsSize: U.readU32(bytes, 64),
      protoIdsSize: U.readU32(bytes, 72),
      fieldIdsSize: U.readU32(bytes, 80),
      methodIdsSize: U.readU32(bytes, 88),
      classDefsSize: U.readU32(bytes, 96),
      dataSize: U.readU32(bytes, 104),
      dataOff: U.readU32(bytes, 108)
    };
  }
  function uleb128(bytes, offset) {
    let result = 0, shift = 0, cursor = offset;
    while (cursor < bytes.length && shift < 35) {
      const byte = bytes[cursor++];
      result |= (byte & 0x7f) << shift;
      if (!(byte & 0x80)) break;
      shift += 7;
    }
    return { value: result >>> 0, next: cursor };
  }
  function decodeMutf8(bytes) {
    let result = '';
    for (let i = 0; i < bytes.length; i++) {
      const byte = bytes[i];
      if (byte < 0x80) { result += String.fromCharCode(byte); continue; }
      if ((byte & 0xe0) === 0xc0 && i + 1 < bytes.length) { result += String.fromCharCode(((byte & 0x1f) << 6) | (bytes[++i] & 0x3f)); continue; }
      if ((byte & 0xf0) === 0xe0 && i + 2 < bytes.length) {
        result += String.fromCharCode(((byte & 0x0f) << 12) | ((bytes[++i] & 0x3f) << 6) | (bytes[++i] & 0x3f));
        continue;
      }
      if ((byte & 0xf8) === 0xf0 && i + 3 < bytes.length) {
        const code = ((byte & 0x07) << 18) | ((bytes[++i] & 0x3f) << 12) | ((bytes[++i] & 0x3f) << 6) | (bytes[++i] & 0x3f);
        result += String.fromCodePoint(code);
        continue;
      }
      if (i + 1 < bytes.length) result += String.fromCharCode(byte);
    }
    return result;
  }
  function readDexStrings(bytes, header, maxStrings) {
    const strings = [];
    const count = Math.min(header.stringIdsSize, maxStrings);
    for (let i = 0; i < count; i++) {
      const offset = U.readU32(bytes, header.stringIdsOff + i * 4);
      if (offset + 1 >= bytes.length) continue;
      const length = uleb128(bytes, offset);
      let end = length.next;
      while (end < bytes.length && bytes[end] !== 0) end++;
      if (end <= length.next) continue;
      strings.push(decodeMutf8(bytes.subarray(length.next, end)));
    }
    return strings;
  }

  async function inspectDex(source, entries, state) {
    const dexEntries = entries.filter(entry => /^classes\d*\.dex$/.test(entry.name));
    const result = [];
    let scannedBytes = 0;
    for (const [index, entry] of dexEntries.entries()) {
      const info = { name: entry.name, size: entry.size, version: null, checksumValid: null, sha1Valid: null, header: null, stringsScanned: 0, classes: null, methods: null };
      try {
        if (entry.size > LIMITS.dexBytes) {
          state.warnings.push(entry.name + ' 超过 ' + U.formatBytes(LIMITS.dexBytes) + '，仅读取文件头。');
          const head = await Api.zip.readEntryPrefix(source, entry, 112);
          Object.assign(info, readDexHeader(head));
          info.scanSkipped = true;
        } else {
          const bytes = await Api.zip.readEntry(source, entry, { maxSize: LIMITS.dexBytes });
          const header = readDexHeader(bytes);
          info.header = header;
          info.version = header.version;
          info.classes = header.classDefsSize;
          info.methods = header.methodIdsSize;
          info.fileSize = header.fileSize;
          info.checksumValid = U.adler32(bytes.subarray(12)) === header.checksum;
          info.sha1Valid = Api.hash.hex('sha1', bytes.subarray(32)) === header.signature;
          if (!info.checksumValid || !info.sha1Valid) {
            state.warnings.push(entry.name + ' 的 DEX 头部校验和或 SHA-1 与文件内容不一致；文件可能被修改、加固或损坏，反编译结果也需谨慎使用。');
          }
          if (scannedBytes + bytes.length <= LIMITS.dexTotalBytes) {
            const strings = readDexStrings(bytes, header, Math.max(0, LIMITS.dexStrings - state.dexStringCount));
            info.stringsScanned = strings.length;
            state.dexStringCount += strings.length;
            for (const value of strings) {
              if (!value || value.length < 4 || value.length > 500) continue;
              scanText(value, entry.name + (index ? '#' + (index + 1) : ''), state);
            }
            scannedBytes += bytes.length;
          } else {
            info.scanSkipped = true;
            state.warnings.push(entry.name + ' 使 DEX 文本扫描达到 ' + U.formatBytes(LIMITS.dexTotalBytes) + ' 上限，后续 DEX 未扫描字符串。');
          }
        }
      } catch (error) {
        state.warnings.push('DEX 解析失败（' + entry.name + '）：' + error.message);
      }
      result.push(info);
    }
    return result;
  }

  /* ------------------------------------------------------------------ */
  /* 内容清单                                                             */
  /* ------------------------------------------------------------------ */

  const NESTED_ARCHIVE = /\.(?:apk|apks|xapk|zip|jar|aar|odex|vdex|dex|so)$/i;
  const SENSITIVE_EXT = /\.(?:pem|cer|crt|p12|pfx|jks|bks|keystore|key|der|db|sqlite|sqlite3|realm|env|properties|yml|yaml|ini|conf|json|xml|html|js|py|sh|bat|ps1|txt|log|cfg)$/i;
  const DB_EXT = /\.(?:db|sqlite|sqlite3|realm)$/i;
  const KEY_EXT = /\.(?:pem|cer|crt|p12|pfx|jks|bks|keystore|key|der)$/i;
  const SCRIPT_EXT = /\.(?:js|py|sh|bat|ps1|lua|pl)$/i;

  function detectKind(entry, magic) {
    const name = entry.name.toLowerCase();
    const hex = magic ? U.hex(magic.subarray(0, 8)) : '';
    if (hex.startsWith('89504E47')) return 'PNG 图片';
    if (hex.startsWith('FFD8FF')) return 'JPEG 图片';
    if (hex.startsWith('47494638')) return 'GIF 图片';
    if (hex.startsWith('52494646')) return 'RIFF 容器';
    if (hex.startsWith('504B0304')) return 'ZIP/JAR 容器';
    if (hex.startsWith('6465780A')) return 'DEX 字节码';
    if (hex.startsWith('7F454C46')) return 'ELF 原生库';
    if (hex.startsWith('25504446')) return 'PDF 文档';
    if (hex.startsWith('53514C697465')) return 'SQLite 数据库';
    if (hex.startsWith('03000800')) return '二进制 XML';
    if (hex.startsWith('3C3F786D6C') || hex.startsWith('3C6D616E')) return 'XML 文本';
    if (name.endsWith('.so')) return 'ELF 原生库';
    if (name.endsWith('.json')) return 'JSON 文本';
    if (name.endsWith('.html') || name.endsWith('.htm')) return 'HTML 文本';
    if (name.endsWith('.js')) return 'JavaScript 文本';
    if (/\.(?:txt|log|md|csv|ini|cfg|conf|properties|yml|yaml)$/.test(name)) return '文本文件';
    if (/\.(?:bin|dat|img|raw)$/.test(name)) return '二进制数据';
    if (name.endsWith('.apk') || name.endsWith('.zip') || name.endsWith('.jar')) return '嵌套归档';
    return '未知/二进制';
  }
  function abiFromPath(name) {
    const match = /^lib\/([^/]+)\//.exec(name.replace(/\\/g, '/'));
    return match ? match[1] : '';
  }
  function elfInfo(bytes) {
    if (bytes.length < 20 || bytes[0] !== 0x7f || bytes[1] !== 0x45 || bytes[2] !== 0x4c || bytes[3] !== 0x46) return null;
    const is64 = bytes[4] === 2;
    const little = bytes[5] === 1;
    const machine = little ? (bytes[18] | (bytes[19] << 8)) : ((bytes[18] << 8) | bytes[19]);
    const machineName = { 0x28: 'ARM', 0xb7: 'AArch64', 0x03: 'x86', 0x3e: 'x86-64', 0x08: 'MIPS', 0xf3: 'RISC-V' }[machine] || ('machine 0x' + machine.toString(16));
    return { bits: is64 ? 64 : 32, endian: little ? 'little' : 'big', machine: machineName };
  }
  function suspiciousReason(entry, kind) {
    const reasons = [];
    const name = entry.name;
    if (name.includes('\\')) reasons.push('路径含反斜杠');
    if (name.startsWith('/')) reasons.push('绝对路径');
    if (name.split('/').includes('..')) reasons.push('路径含 ..');
    if (/(^|\/)\./.test(name)) reasons.push('隐藏文件或隐藏目录');
    if (NESTED_ARCHIVE.test(name) && !name.startsWith('lib/') && !/^classes\d*\.dex$/.test(name)) reasons.push('内嵌可执行/归档内容');
    if (DB_EXT.test(name)) reasons.push('数据库文件');
    if (KEY_EXT.test(name)) reasons.push('密钥/证书文件');
    if (SCRIPT_EXT.test(name)) reasons.push('脚本文件');
    if (/\.(png|jpg|jpeg|webp|gif)\.(apk|dex|jar|zip|so|txt|json)$/i.test(name)) reasons.push('双重扩展名');
    if (entry.encrypted) reasons.push('ZIP 加密条目');
    if (entry.compressedSize > 0 && entry.size / entry.compressedSize > 100 && entry.size > 1024 * 1024) reasons.push('压缩比异常（可能为压缩炸弹）');
    if (name.startsWith('assets/') && kind === 'ELF 原生库') reasons.push('assets 中的原生库');
    return reasons;
  }

  async function inspectInventory(source, directory, state) {
    const entries = directory.entries;
    const groups = new Map();
    const groupOf = name => {
      if (/^classes\d*\.dex$/.test(name)) return 'DEX 字节码';
      if (name === 'AndroidManifest.xml') return '清单与资源表';
      if (name === 'resources.arsc') return '清单与资源表';
      if (name.startsWith('assets/')) return 'assets';
      if (name.startsWith('res/')) return 'res 资源';
      if (name.startsWith('lib/')) return '原生库';
      if (name.startsWith('META-INF/')) return 'META-INF';
      if (name.startsWith('kotlin/')) return 'Kotlin 元数据';
      return '其他文件';
    };
    for (const entry of entries) {
      if (entry.isDirectory) continue;
      const group = groupOf(entry.name.replace(/\\/g, '/'));
      if (!groups.has(group)) groups.set(group, { name: group, count: 0, size: 0 });
      const item = groups.get(group);
      item.count++;
      item.size += entry.size;
    }
    const topLevel = [...groups.values()].sort((a, b) => b.size - a.size);
    const names = new Set();
    const duplicates = [];
    for (const entry of entries) {
      if (names.has(entry.name)) duplicates.push(entry.name);
      names.add(entry.name);
    }
    const encrypted = entries.filter(entry => entry.encrypted).map(entry => entry.name);
    const timestamps = entries.map(entry => entry.dosTime).filter(Boolean).sort();
    const assets = [];
    const raw = [];
    const nativeLibs = [];
    const metaInf = [];
    const suspicious = [];
    const others = [];
    let assetScanBytes = 0;
    let hashBudget = 64 * 1024 * 1024;
    const counters = { assets: 0, raw: 0, nativeLibs: 0, metaInf: 0, suspicious: 0 };

    for (const entry of entries) {
      if (entry.isDirectory) continue;
      const normalizedName = entry.name.replace(/\\/g, '/');
      const inAssets = normalizedName.startsWith('assets/');
      const inRaw = normalizedName.startsWith('res/raw/');
      const inLib = normalizedName.startsWith('lib/');
      const inMeta = normalizedName.startsWith('META-INF/');
      if (inMeta) { counters.metaInf++; metaInf.push({ name: entry.name, size: entry.size, method: entry.method, sha256: null }); }
      if (!inAssets && !inRaw && !inLib && !inMeta) {
        const known = normalizedName === 'AndroidManifest.xml' || normalizedName === 'resources.arsc' || normalizedName.startsWith('res/') || /^classes\d*\.dex$/.test(normalizedName) || normalizedName.startsWith('kotlin/');
        if (!known && others.length < 200) others.push({ name: entry.name, size: entry.size });
      }
      if (!inAssets && !inRaw && !inLib) {
        if (suspicious.length < 200) {
          const reasons = suspiciousReason(entry, null);
          if (reasons.length) { suspicious.push({ name: entry.name, size: entry.size, reasons }); counters.suspicious++; }
        }
        continue;
      }
      if (inLib) counters.nativeLibs++;
      else if (inAssets) counters.assets++;
      else if (inRaw) counters.raw++;
      const item = {
        name: entry.name,
        size: entry.size,
        compressedSize: entry.compressedSize,
        method: entry.method,
        timestamp: entry.dosTime,
        sha256: null,
        kind: null,
        preview: null,
        findings: [],
        elf: null,
        abi: inLib ? abiFromPath(entry.name) : null
      };
      try {
        if (inLib) {
          const head = await Api.zip.readEntryPrefix(source, entry, 4096);
          item.elf = elfInfo(head);
          item.kind = 'ELF 原生库';
          if (entry.size <= LIMITS.assetHashBytes && hashBudget >= entry.size) {
            const bytes = await Api.zip.readEntry(source, entry, { maxSize: LIMITS.assetHashBytes });
            item.sha256 = Api.hash.hex('sha256', bytes);
            hashBudget -= entry.size;
          }
          if (nativeLibs.length < LIMITS.assets) nativeLibs.push(item);
        } else {
          let bytes;
          if (entry.size <= LIMITS.assetHashBytes) {
            bytes = await Api.zip.readEntry(source, entry, { maxSize: LIMITS.assetHashBytes });
            if (hashBudget >= entry.size) {
              item.sha256 = Api.hash.hex('sha256', bytes);
              hashBudget -= entry.size;
            }
          } else {
            bytes = await Api.zip.readEntryPrefix(source, entry, LIMITS.assetScanBytes);
            item.note = '文件超过 ' + U.formatBytes(LIMITS.assetHashBytes) + '，仅读取前 ' + U.formatBytes(bytes.length) + '。';
          }
          item.kind = detectKind(entry, bytes.subarray(0, 8));
          const reasons = suspiciousReason(entry, item.kind);
          if (reasons.length && suspicious.length < 200) suspicious.push({ name: entry.name, size: entry.size, reasons });
          if ((inAssets || inRaw) && assetScanBytes < 32 * 1024 * 1024) {
            const scanBytes = bytes.subarray(0, LIMITS.assetScanBytes);
            const text = U.utf8(scanBytes);
            if (U.isPrintableText(scanBytes)) {
              item.preview = text.slice(0, 500).replace(/\0/g, '');
              const before = state.secrets.length + state.urls.length;
              scanText(text, entry.name, state);
              if (state.secrets.length + state.urls.length > before) {
                item.findings = state.secrets.filter(secret => secret.source === entry.name).map(secret => secret.label);
              }
              assetScanBytes += scanBytes.length;
            } else if (item.kind === 'SQLite 数据库' || /\.(db|sqlite|sqlite3|realm)$/i.test(entry.name)) {
              item.preview = '数据库文件：未解析表结构；可在本机使用 SQLite 工具进一步检查。';
            }
          }
          if (inAssets) { if (assets.length < LIMITS.assets) assets.push(item); }
          else if (inRaw) { if (raw.length < LIMITS.assets) raw.push(item); }
        }
      } catch (error) {
        item.error = error.message;
        if (inAssets && assets.length < LIMITS.assets) assets.push(item);
        else if (inRaw && raw.length < LIMITS.assets) raw.push(item);
        else if (inLib && nativeLibs.length < LIMITS.assets) nativeLibs.push(item);
      }
    }

    const dexEntries = entries.filter(entry => /^classes\d*\.dex$/.test(entry.name));
    const metaVersions = [];
    for (const entry of entries) {
      if (!entry.name.startsWith('META-INF/') || entry.isDirectory) continue;
      if (!/\.version$/i.test(entry.name) && !/app-metadata\.properties$/i.test(entry.name)) continue;
      if (metaVersions.length >= 200) break;
      try {
        const bytes = await Api.zip.readEntry(source, entry, { maxSize: 64 * 1024 });
        const value = U.utf8(bytes).trim().replace(/\u0000/g, '');
        if (value) metaVersions.push({ name: entry.name.slice('META-INF/'.length), value: value.slice(0, 500) });
      } catch { /* 单个版本文件失败不影响整体 */ }
    }
    const keyFiles = [];
    const keyNames = ['AndroidManifest.xml', 'resources.arsc', ...dexEntries.map(entry => entry.name)];
    for (const name of keyNames) {
      const entry = entries.find(item => item.name === name);
      if (entry) keyFiles.push({ name: entry.name, size: entry.size, sha256: null });
    }
    for (const file of keyFiles) {
      try {
        const entry = entries.find(item => item.name === file.name);
        if (entry && entry.size <= 128 * 1024 * 1024) {
          const bytes = await Api.zip.readEntry(source, entry, { maxSize: 128 * 1024 * 1024 });
          file.sha256 = Api.hash.hex('sha256', bytes);
        }
      } catch { /* 单项失败不影响整体 */ }
    }
    let totalSize = 0, totalCompressed = 0;
    for (const entry of entries) { if (!entry.isDirectory) { totalSize += entry.size; totalCompressed += entry.compressedSize; } }

    return {
      counts: {
        assets: counters.assets,
        raw: counters.raw,
        nativeLibs: counters.nativeLibs,
        metaInf: counters.metaInf
      },
      zip: {
        entryCount: directory.entryCount,
        parsedEntries: entries.length,
        directoryTruncated: directory.truncated,
        comment: directory.comment,
        commentBytes: directory.commentBytes,
        zip64: directory.zip64,
        centralDirectoryOffset: directory.cdOffset,
        eocdOffset: directory.eocdOffset,
        totalUncompressed: totalSize,
        totalCompressed,
        duplicateNames: duplicates.slice(0, 100),
        encryptedEntries: encrypted.slice(0, 100),
        timestamps: { first: timestamps[0] || null, last: timestamps[timestamps.length - 1] || null },
        compressionMethods: countMethods(entries)
      },
      topLevel,
      keyFiles,
      assets,
      raw,
      nativeLibs,
      metaInf,
      metaVersions,
      suspicious,
      others,
      dexEntries
    };
  }
  function countMethods(entries) {
    const methods = new Map();
    for (const entry of entries) {
      if (entry.isDirectory) continue;
      const name = entry.method === 0 ? 'stored (0)' : entry.method === 8 ? 'deflate (8)' : 'method ' + entry.method;
      methods.set(name, (methods.get(name) || 0) + 1);
    }
    return [...methods.entries()].map(([name, count]) => ({ name, count }));
  }

  /* ------------------------------------------------------------------ */
  /* 安全线索                                                             */
  /* ------------------------------------------------------------------ */

  function buildNotes(manifest, signature, inventory, state) {
    const notes = [];
    const app = manifest.application || {};
    const push = (severity, title, detail) => notes.push({ severity, title, detail });
    if (app.debuggable === true) push('high', '应用声明可调试', 'android:debuggable="true" 允许调试器附加并访问应用进程，通常不应出现在正式发布包中。');
    if (app.testOnly === true) push('warning', '测试专用包', 'android:testOnly="true" 表明该 APK 面向测试，系统可能拒绝常规安装。');
    if (app.allowBackup === true) push('info', '允许系统备份应用数据', 'android:allowBackup 未关闭；取证时可结合备份规则评估可导出的数据范围。');
    if (app.usesCleartextTraffic === true) push('warning', '允许明文 HTTP 流量', 'android:usesCleartextTraffic="true" 允许应用使用未加密的 HTTP；还需结合 networkSecurityConfig 判断。');
    if (manifest.sharedUserId) push('info', '共享 Linux 用户 ID', 'android:sharedUserId="' + manifest.sharedUserId + '" 使该应用与同一签名的应用共享数据目录。');
    if ((manifest.targetSdk ?? 0) < 31 && signature.schemes?.v2?.present === false && signature.schemes?.v3?.present === false) {
      push('info', '未发现 APK Signature Scheme v2/v3', '目标 SDK 低于 31；Android 11 及以上通常要求 v2 或更高签名方案。');
    }
    const exported = [
      ...manifest.activities, ...manifest.activityAliases, ...manifest.services, ...manifest.receivers, ...manifest.providers
    ].filter(component => component.exported);
    const exportedWithoutPermission = exported.filter(component => !component.permission && !component.readPermission && !component.writePermission);
    if (exportedWithoutPermission.length) {
      push('info', '存在导出且未声明权限的组件', exportedWithoutPermission.length + ' 个组件可被其他应用调用（Activity/Service/Receiver/Provider），是否构成风险取决于组件实现。');
    }
    if (manifest.usesPermissions.some(permission => permission.name === 'android.permission.MANAGE_EXTERNAL_STORAGE')) {
      push('info', '申请管理所有文件权限', 'MANAGE_EXTERNAL_STORAGE 属于特殊访问权限，需用户在系统设置中单独授权。');
    }
    if (manifest.usesPermissions.some(permission => permission.name === 'android.permission.REQUEST_INSTALL_PACKAGES')) {
      push('info', '申请安装 APK 权限', 'REQUEST_INSTALL_PACKAGES 允许应用请求安装其他 APK，需结合下载与校验逻辑分析。');
    }
    if (signature.debugCertificate) push('warning', '使用调试证书签名', '签名证书主题或颁发者包含 Android Debug 特征，常见于开发构建。');
    if (inventory.assets.some(asset => /\.(apk|dex|jar|so)$/i.test(asset.name))) push('info', 'assets 中包含可执行内容', 'assets 目录存在 APK/DEX/JAR/SO 等文件，可能由运行时动态加载。');
    if (state.secrets.length) push('info', '发现疑似敏感字符串', '共 ' + state.secrets.length + ' 条命中（Flag、密钥、口令或令牌形式），需人工确认是否为真实凭据。');
    return notes;
  }

  /* ------------------------------------------------------------------ */
  /* 主流程                                                               */
  /* ------------------------------------------------------------------ */

  async function inspect(source, options = {}) {
    const startedAt = Date.now();
    const state = {
      warnings: [],
      secrets: [],
      secretSeen: new Set(),
      urls: [],
      urlSeen: new Set(),
      emails: [],
      emailSeen: new Set(),
      ips: [],
      ipSeen: new Set(),
      paths: [],
      pathSeen: new Set(),
      dexStringCount: 0
    };
    const report = { tool: 'simplerforensics-apk-inspect', version: 1, generatedAt: new Date().toISOString(), file: {} };
    const progress = (phase, percent, message) => options.onProgress?.({ phase, percent, message });
    const checkAbort = () => { if (options.signal?.aborted) throw new DOMException('已取消', 'AbortError'); };

    U.checkSource(source);
    if (options.signal?.aborted) throw new DOMException('已取消', 'AbortError');
    report.file = { name: source.name || 'input.apk', size: source.size, lastModified: source.lastModified || null };

    progress('zip', 2, '读取 ZIP 中央目录');
    const directory = await Api.zip.readDirectory(source, { maxEntries: 60000 });
    if (directory.truncated) state.warnings.push('ZIP 条目数量超过上限，后续清单仅基于前 ' + directory.entries.length + ' 个条目。');
    report.zip = {
      entryCount: directory.entryCount,
      parsedEntries: directory.entries.length,
      truncated: directory.truncated,
      comment: directory.comment,
      commentBytes: directory.commentBytes,
      zip64: directory.zip64,
      centralDirectoryOffset: directory.cdOffset,
      eocdOffset: directory.eocdOffset
    };

    progress('manifest', 6, '解析 AndroidManifest.xml');
    let manifest = null;
    const manifestEntry = directory.entries.find(entry => entry.name === 'AndroidManifest.xml');
    if (!manifestEntry) {
      state.warnings.push('APK 中没有 AndroidManifest.xml，可能不是 Android 应用包。');
    } else {
      try {
        const manifestBytes = await Api.zip.readEntry(source, manifestEntry, { maxSize: 64 * 1024 * 1024 });
        report.manifestFile = {
          path: manifestEntry.name,
          size: manifestEntry.size,
          compressedSize: manifestEntry.compressedSize,
          method: manifestEntry.method,
          timestamp: manifestEntry.dosTime,
          sha256: Api.hash.hex('sha256', manifestBytes)
        };
        const document = Api.axml.parse(manifestBytes);
        report.manifestDocument = { namespaces: document.namespaces, stringCount: document.strings.length, resourceMapCount: document.resourceMap.length };
        progress('resources', 10, '解析 resources.arsc 资源表');
        const arscEntry = directory.entries.find(entry => entry.name === 'resources.arsc');
        let table = null;
        if (arscEntry) {
          try {
            const arscBytes = await Api.zip.readEntry(source, arscEntry, { maxSize: 64 * 1024 * 1024 });
            table = Api.arsc.parse(arscBytes);
            report.resourceTable = {
              size: arscEntry.size,
              packageCount: table.packageCount,
              resourceCount: table.resourceCount,
              stringCount: table.stringCount,
              packages: table.packages.map(pkg => ({ id: pkg.id, name: pkg.name })),
              sha256: Api.hash.hex('sha256', arscBytes)
            };
            const strings = Api.arsc.collectStringResources(table, LIMITS.resourceStrings);
            report.resources = {
              totalStrings: strings.total,
              locales: strings.locales,
              items: strings.items,
              collected: strings.items.length,
              truncated: strings.total > strings.items.length
            };
            for (const item of strings.items) scanText(item.value, 'resources.arsc:' + item.name + '(' + item.config + ')', state);
          } catch (error) {
            state.warnings.push('resources.arsc 解析失败：' + error.message);
          }
        }
        manifest = normalizeManifest(document, table, {});
        if (manifest.appIcon?.text) {
          const iconPath = manifest.appIcon.text;
          const iconEntry = directory.entries.find(entry => entry.name === iconPath || entry.name.replace(/\\/g, '/') === iconPath);
          if (iconEntry && iconEntry.size <= 4 * 1024 * 1024) {
            try {
              const iconBytes = await Api.zip.readEntry(source, iconEntry, { maxSize: 4 * 1024 * 1024 });
              manifest.appIcon.file = {
                name: iconEntry.name,
                size: iconEntry.size,
                sha256: Api.hash.hex('sha256', iconBytes)
              };
            } catch (error) {
              state.warnings.push('图标文件读取失败：' + error.message);
            }
          }
        }
        if (manifest.rawXml.length > LIMITS.rawXmlBytes) manifest.rawXml = manifest.rawXml.slice(0, LIMITS.rawXmlBytes) + '\n<!-- 已截断 -->';
        if (manifest.appLabel) scanText(manifest.appLabel.text, 'AndroidManifest.xml:label', state);
      } catch (error) {
        state.warnings.push('AndroidManifest.xml 解析失败：' + error.message);
      }
    }
    report.manifest = manifest;
    checkAbort();

    progress('signature', 18, '读取签名块与证书');
    try {
      report.signature = await Api.signature.analyzeSignature(source, directory);
      if (report.signature.warnings?.length) state.warnings.push(...report.signature.warnings);
    } catch (error) {
      report.signature = { error: error.message, certificates: [], schemes: {} };
      state.warnings.push('签名分析失败：' + error.message);
    }
    checkAbort();

    progress('inventory', 28, '整理 APK 内容清单');
    const inventory = await inspectInventory(source, directory, state);
    report.inventory = inventory;
    report.zip = { ...report.zip, ...inventory.zip };
    delete report.inventory.zip;
    checkAbort();

    progress('assets', 40, '扫描 assets、原生库与 DEX');
    const dex = await inspectDex(source, directory.entries, state);
    report.dex = dex;
    checkAbort();

    progress('hash', 60, '计算整包摘要（MD5 / SHA-1 / SHA-256）');
    try {
      report.hashes = await Api.hash.hashSource(source, {
        signal: options.signal,
        onProgress: item => progress('hash', 60 + Math.floor(item.percent * 0.36), '计算整包摘要（' + item.percent + '%）')
      });
    } catch (error) {
      if (error.name === 'AbortError') throw error;
      report.hashes = { error: error.message };
      state.warnings.push('整包摘要计算失败：' + error.message);
    }

    progress('finalize', 98, '汇总检查结果');
    if (manifest) {
      for (const permission of manifest.usesPermissions) {
        if (!permission.name) continue;
        scanText(permission.name, 'AndroidManifest.xml:uses-permission', state);
      }
    }
    report.strings = {
      secrets: state.secrets,
      urls: state.urls,
      ips: state.ips,
      emails: state.emails,
      paths: state.paths,
      dexStringsScanned: state.dexStringCount
    };
    report.notes = buildNotes(manifest || { application: {} }, report.signature || {}, inventory, state);
    report.warnings = state.warnings;
    report.limits = LIMITS;
    report.elapsed = Date.now() - startedAt;
    report.statistics = {
      entries: directory.entries.length,
      assets: inventory.counts?.assets ?? inventory.assets.length,
      nativeLibs: inventory.counts?.nativeLibs ?? inventory.nativeLibs.length,
      dexFiles: dex.length,
      components: manifest ? Object.values(manifest.componentCount).reduce((sum, value) => sum + value, 0) : 0,
      permissions: manifest ? manifest.usesPermissions.length : 0,
      certificates: report.signature?.certificates?.length || 0,
      secretHits: state.secrets.length,
      urls: state.urls.length
    };
    progress('complete', 100, '检查完成');
    return report;
  }

  Object.assign(Api, {
    inspect,
    manifest: { normalizeManifest },
    scanText,
    LIMITS,
    RULES: { SECRET_RULES }
  });
  if (typeof module === 'object' && module.exports) module.exports = Api;
})();
