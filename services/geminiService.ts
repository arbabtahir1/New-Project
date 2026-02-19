
import { GoogleGenAI, Type } from "@google/genai";

const ai = new GoogleGenAI({ apiKey: process.env.API_KEY });

export const analyzeSecurityThreat = async (type: 'URL' | 'APK' | 'PDF', data: any) => {
  const depth = data.depth || 'Standard';
  
  const systemInstruction = `You are the World's lead Security Architect. You analyze files/URLs for a high-security audience. 
  When providing "engines", you MUST act as a multi-engine aggregator (like VirusTotal). 
  Select 8-12 famous security vendors (e.g., Sophos, Bitdefender, CrowdStrike, Kaspersky, Fortinet, Symantec) and assign them a realistic result based on the threat level.
  Threat names should look professional (e.g., "Trojan.Android.Generic.A", "Phishing.URL.Heuristic").`;

  let prompt = "";
  if (type === 'URL') {
    prompt = `AUDIT URL: ${data.url}. DEPTH: ${depth}. Provide 0-100 risk score. If Deep, analyze potential C2 redirection and obfuscated JS.`;
  } else if (type === 'APK') {
    prompt = `AUDIT APK: ${data.packageName}. HASH: ${data.hash}. PERMISSIONS: ${data.permissions_detected?.join(', ') || 'None'}. Analyze permission overreach.`;
  } else if (type === 'PDF') {
    prompt = `AUDIT PDF: ${data.filename}. HASH: ${data.hash}. Analyze for embedded exploit markers.`;
  }

  try {
    // Perform complex text task (security analysis) using the recommended Pro model
    const response = await ai.models.generateContent({
      model: 'gemini-3-pro-preview',
      contents: prompt,
      config: {
        systemInstruction,
        responseMimeType: "application/json",
        responseSchema: {
          type: Type.OBJECT,
          properties: {
            riskScore: { type: Type.NUMBER },
            summary: { type: Type.STRING },
            insights: { type: Type.STRING },
            threats: { type: Type.ARRAY, items: { type: Type.STRING } },
            engines: {
              type: Type.ARRAY,
              items: {
                type: Type.OBJECT,
                properties: {
                  engine: { type: Type.STRING },
                  category: { type: Type.STRING, description: "malicious, suspicious, undetected" },
                  result: { type: Type.STRING },
                  method: { type: Type.STRING }
                },
                required: ["engine", "category", "method"]
              }
            }
          },
          required: ["riskScore", "summary", "insights", "engines"]
        }
      }
    });

    // Correctly extract the generated text content from the response object as a property
    return JSON.parse(response.text || '{}');
  } catch (error) {
    console.error("Forensic Engine Error:", error);
    return null;
  }
};
