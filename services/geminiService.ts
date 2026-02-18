
import { GoogleGenAI, Type } from "@google/genai";

const ai = new GoogleGenAI({ apiKey: process.env.API_KEY || '' });

export const analyzeSecurityThreat = async (type: 'URL' | 'APK' | 'PDF', data: any) => {
  const model = 'gemini-3-flash-preview';
  
  let prompt = "";
  if (type === 'URL') {
    prompt = `Analyze the following URL for security risks: ${data.url}. 
              Provide a risk score from 0 to 100 and a concise summary of potential threats (phishing, malware, etc.).`;
  } else if (type === 'APK') {
    prompt = `Perform a static analysis on this APK metadata:
              Package: ${data.packageName}
              Permissions: ${data.permissions.join(', ')}
              SHA-256: ${data.hash}
              
              Provide a risk score from 0 to 100 based on permission overreach and known suspicious package patterns. 
              Return insights in a structured way.`;
  } else if (type === 'PDF') {
    prompt = `Perform a security analysis on this PDF document metadata:
              Filename: ${data.filename}
              Author: ${data.author}
              SHA-256: ${data.hash}
              Embedded Links: ${data.embeddedLinks.join(', ') || 'None'}
              
              Assess if this PDF is likely a phishing lure or contains malicious redirection. 
              Provide a risk score from 0 to 100 and identify specific threats.`;
  }

  try {
    const response = await ai.models.generateContent({
      model,
      contents: prompt,
      config: {
        responseMimeType: "application/json",
        responseSchema: {
          type: Type.OBJECT,
          properties: {
            riskScore: { type: Type.NUMBER },
            summary: { type: Type.STRING },
            insights: { type: Type.STRING },
            threats: { 
              type: Type.ARRAY, 
              items: { type: Type.STRING } 
            }
          },
          required: ["riskScore", "summary", "insights"]
        }
      }
    });

    return JSON.parse(response.text || '{}');
  } catch (error) {
    console.error("Gemini Security Analysis Error:", error);
    return {
      riskScore: 50,
      summary: "Local analysis only. AI insights currently unavailable.",
      insights: "Analyze internal markers manually."
    };
  }
};
