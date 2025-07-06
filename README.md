

const fs = require('fs').promises;
const path = require('path');
const axios = require('axios');
const crypto = require('crypto');
const FormData = require('form-data');
const { bot, isAdmin } = require('../lib');

// Idioma Dinamico.
const defaultMessages = {
  invalidApiKey: "❌ Quote File to Scan. \nGet your KEY here:\nhttps://www.virustotal.com/gui/my-apikey \nSet it with setvar VIRUS_API_KEY = (paste key)",
  fileTooLarge: "The file is too large. Max ({maxSize} MB).",
  uploadingFile: "🔍 Analyzing...",
  analysisFailed: "❌ Error analyzing the file.",
  resultsTitle: "📊 Analysis results:",
  status: "🔄 Status: {status}",
  malicious: "🔴 Malicious: {malicious}",
  suspicious: "⚠️ Suspicious: {suspicious}",
  harmless: "✅ Harmless: {harmless}",
  totalAntivirus: "📝 Total Antivirus: {total}",
  moreDetails: "🔍 More Details: {link}",
  warning: "⚠️ *WARNING!* The file might be malicious. \n_Check Behavior Details in Link._",
  messageDeleted: "❌ The malicious file has been deleted from the chat.",
  notAdmin: "> I am not an admin, The malicious file remains in the chat."
};

class LanguageHandler {
  constructor(defaultMessages) {
    this.defaultMessages = defaultMessages; 
    this.language = process.env.LANGUAG || 'default'; 
    this.messages = {};
    this.langFilePath = path.join(__dirname, '..', 'media', 'LANGS', 'Virus', `${this.language}.json`);
  }

  async loadMessages() {
    try {
      const data = await fs.readFile(this.langFilePath, 'utf8');
      this.messages = JSON.parse(data);
    } catch (error) {
      console.warn(`Language file for '${this.language}' not found or invalid. Using default messages from the script.`);
      this.messages = {}; 
    }
  }

  getMessage(key, replacements = {}) {
    let message = this.messages[key] || this.defaultMessages[key]; 
    for (const [placeholder, value] of Object.entries(replacements)) {
      message = message.replace(new RegExp(`{${placeholder}}`, 'g'), value);
    }
    return message || `Missing message for key: ${key}`;
  }
}


class VirusTotalHandler {
  constructor(languageHandler) {
    this.config = {
      apiKey: process.env.VIRUS_API_KEY || null,
      maxFileSize: (parseInt(process.env.MAX_UPLOAD, 10) * 1048576) || 524288000,
      tempDir: process.env.TEMP_DOWNLOAD_DIR || path.join(process.cwd(), 'tmp'),
      apiBaseUrl: 'https://www.virustotal.com/api/v3',
      maxRegularFileSize: 33554432 //#
    };
    this.languageHandler = languageHandler;
  }

  checkConfig() {
    if (!this.config.apiKey) {
      throw new Error(this.languageHandler.getMessage('invalidApiKey'));
    }

    if (!this.config.apiKey.match(/[0-9a-z]{64}/)) {
      throw new Error(this.languageHandler.getMessage('invalidApiKey'));
    }
  }

  async isFileSizeValid(filePath) {
    try {
      const { size } = await fs.stat(filePath);
      return size <= this.config.maxFileSize;
    } catch (error) {
      console.error(`VirusPlugin Error checking file ${filePath}:`, error);
      return false;
    }
  }

  async getFileSize(filePath) {
    const stats = await fs.stat(filePath);
    return stats.size;
  }

  async getUploadUrl() {
    try {
      const response = await axios.get(`${this.config.apiBaseUrl}/files/upload_url`, {
        headers: {
          'accept': 'application/json',
          'x-apikey': this.config.apiKey
        }
      });
      return response.data.data;
    } catch (error) {
      console.error('VirusPlugin Error getting upload URL:', error);
      throw error;
    }
  }

  async uploadFile(filePath) {
    try {
      const fileSize = await this.getFileSize(filePath);
      const formData = new FormData();
      const fileStream = await fs.readFile(filePath);
      formData.append('file', fileStream, path.basename(filePath));
      let uploadUrl = `${this.config.apiBaseUrl}/files`;
      if (fileSize > this.config.maxRegularFileSize) {
        uploadUrl = await this.getUploadUrl();
      }
      const response = await axios.post(uploadUrl, formData, {
        headers: {
          'accept': 'application/json',
          'x-apikey': this.config.apiKey,
          ...formData.getHeaders()
        },
        maxBodyLength: Infinity, //#
        maxContentLength: Infinity
      });
      return response.data;
    } catch (error) {
      console.error('VirusPlugin Error uploading file:', error);
      throw error;
    }
  }

  async getAnalysisResults(analysisId) {
    try {
      const response = await axios.get(`${this.config.apiBaseUrl}/analyses/${analysisId}`, {
        headers: {
          'accept': 'application/json',
          'x-apikey': this.config.apiKey
        }
      });
      return response.data;
    } catch (error) {
      console.error('VirusPlugin Error getting analysis results:', error);
      throw error;
    }
  }

  async waitForResults(analysisId) {
    let analysisResults;
    do {
      analysisResults = await this.getAnalysisResults(analysisId);
      const status = analysisResults.data.attributes.status;

      if (status === 'completed') {
        return analysisResults;
      } else if (status === 'failed') {
        throw new Error(this.languageHandler.getMessage('analysisFailed'));
      }

      await new Promise(resolve => setTimeout(resolve, 5000));
    } while (true);
  }

  formatAnalysisResults(results) {
    if (!results?.data?.attributes?.stats) {
      throw new Error(this.languageHandler.getMessage('analysisFailed'));
    }
    const { stats } = results.data.attributes;

    const malicious = stats.malicious || 0;
    const suspicious = stats.suspicious || 0;
    const harmless = (stats.harmless || 0) + (stats.undetected || 0);
    const total = malicious + suspicious + harmless;

    let resultText = `${this.languageHandler.getMessage('resultsTitle')}
${this.languageHandler.getMessage('status', { status: results.data.attributes.status })}
${this.languageHandler.getMessage('malicious', { malicious })}
${this.languageHandler.getMessage('suspicious', { suspicious })}
${this.languageHandler.getMessage('harmless', { harmless })}
${this.languageHandler.getMessage('totalAntivirus', { total })}`;

    if (results.meta?.file_info?.sha256) {
      resultText += `\n${this.languageHandler.getMessage('moreDetails', { link: `https://www.virustotal.com/gui/file/${results.meta.file_info.sha256}` })}`;
    }

    if (malicious > 5) {
      resultText += `\n${this.languageHandler.getMessage('warning')}`;
    }

    return { resultText, malicious };
  }
}

const languageHandler = new LanguageHandler(defaultMessages);

const virusHandler = new VirusTotalHandler(languageHandler);

bot(
  {
    pattern: 'virus ?(.*)',
    fromMe: true,
    desc: 'Analyze files with VirusTotal',
    type: 'security',
  },
  async (message, match) => {
    let tempFilePath = null;
    try {
      await languageHandler.loadMessages();

      virusHandler.checkConfig();
      const quotedMessage = message.reply_message;
      if (!quotedMessage) {
        return await message.send(languageHandler.getMessage('invalidApiKey'));
      }
      await message.send(languageHandler.getMessage('uploadingFile'));

      const mediaBuffer = await quotedMessage.downloadMediaMessage();
      if (!mediaBuffer) {
        throw new Error(languageHandler.getMessage('analysisFailed'));
      }

      const tempFileName = `scan_${Date.now()}${path.extname(quotedMessage.fileName || '') || '.tmp'}`;
      tempFilePath = path.join(virusHandler.config.tempDir, tempFileName);

      await fs.mkdir(path.dirname(tempFilePath), { recursive: true });
      await fs.writeFile(tempFilePath, mediaBuffer);

      if (!(await virusHandler.isFileSizeValid(tempFilePath))) {
        throw new Error(languageHandler.getMessage('fileTooLarge', { maxSize: virusHandler.config.maxFileSize / 1048576 }));
      }

      const uploadResponse = await virusHandler.uploadFile(tempFilePath);
      if (!uploadResponse?.data?.id) {
        throw new Error(languageHandler.getMessage('analysisFailed'));
      }

      const analysisResults = await virusHandler.waitForResults(uploadResponse.data.id);
      const { resultText, malicious } = virusHandler.formatAnalysisResults(analysisResults);


await message.send(resultText, { quoted: message.quoted });

      // borrar mensaje de probabilidad maliciosa
if (malicious > 0 && message.isGroup) {
  const participants = await message.groupMetadata(message.jid);
  const isImAdmin = await isAdmin(participants, message.client.user.jid);
  if (!isImAdmin) {
    return await message.send(languageHandler.getMessage('notAdmin'), { quoted: message.quoted });
  }
  await message.send(quotedMessage.key, {}, 'delete');
  await message.send(languageHandler.getMessage('messageDeleted'), { quoted: message.quoted });
}
    } catch (error) {
      console.error('PluginVirus error:', error);
      await message.send(`❌ ${error.message}`);
    } finally {
      if (tempFilePath) {
        try {
          await fs.unlink(tempFilePath);
          console.log('PluginVirus Temporary file deleted:', tempFilePath);
        } catch (unlinkError) {
          console.error('PluginVirus Error cleaning up temp file:', unlinkError, tempFilePath);
        }
      }
    }
  }
);

module.exports = {};
