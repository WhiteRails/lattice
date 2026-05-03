export interface OverlayMessage {
  id: string;             // Unique message ID
  type: 'request' | 'response';
  source: string;         // e.g. agent:bot1 or relay:xyz
  destination: string;    // e.g. wp://github.white
  
  // The encapsulated HTTP request/response
  payload: {
    method?: string;
    url?: string;
    headers?: Record<string, string>;
    body?: string;
    
    // For response
    status?: number;
  };
  
  // Overlay circuit trace
  trace: string[];
}
