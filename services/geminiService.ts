
import { GoogleGenAI, Type } from "@google/genai";

const ai = new GoogleGenAI({ apiKey: process.env.API_KEY });

export const analyzeSecurityThreat = async (type: 'URL' | 'APK' | 'PDF', data: any) => {
  const depth = data.depth || 'Standard';
  
  const systemInstruction = `You are a world-class security forensic architect at ShadowInspect Labs. 
  You provide professional multi-engine triage results similar to VirusTotal and GitHub Advisory.
  
  Assign risk scores (0-100).
  For the "threats" array, return a list of specific vulnerabilities.
  Format each threat as: "TITLE: DESCRIPTION OF HARM AND IMPACT".
  
  Your "engines" results MUST include detections from at least 3 simulated vendors (e.g., VT Core, UrlScan, GitHub Security).
  
  Your "insights" must warning the investigator about specific forensic anomalies.
  If the input data looks safe, provide a low risk score but identify behavioral best practices.
  Strictly follow the JSON schema. Be professional and objective.`;

  let prompt = "";
  if (type === 'URL') {
    prompt = `AUDIT URL: ${data.url}. RIGOR: ${depth}. Analyze for phishing, credential harvesting, and known C2 redirection patterns. Provide multi-vendor heuristic hits.`;
  } else if (type === 'APK') {
    prompt = `AUDIT APK: ${data.packageName}. HASH: ${data.hash}. PERMISSIONS: ${data.permissions_detected?.join(', ') || 'None'}. Analyze for high-risk permission chaining and potential spyware vectors.`;
  } else if (type === 'PDF') {
    prompt = `AUDIT PDF: ${data.filename}. HASH: ${data.hash}. Analyze for embedded JS exploits, malformed streams, and phishing headers.`;
  }

  try {
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
          required: ["riskScore", "summary", "insights", "engines", "threats"]
        }
      }
    });

    if (!response.text) throw new Error("EMPTY_RESPONSE");
    return JSON.parse(response.text);
  } catch (error: any) {
    // If it's a quota error, rethrow it for the UI to handle the cooldown
    throw error;
  }
};
