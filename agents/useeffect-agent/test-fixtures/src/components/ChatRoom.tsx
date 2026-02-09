import React, { useState, useEffect, useRef } from 'react';

interface Message {
  id: string;
  sender: string;
  text: string;
  timestamp: number;
}

interface ChatRoomProps {
  roomId: string;
  currentUser: string;
}

export function ChatRoom({ roomId, currentUser }: ChatRoomProps) {
  const [messages, setMessages] = useState<Message[]>([]);
  const [inputText, setInputText] = useState('');
  const [isConnected, setIsConnected] = useState(false);
  const messagesEndRef = useRef<HTMLDivElement>(null);
  const wsRef = useRef<WebSocket | null>(null);

  // NECESSARY: WebSocket subscription with cleanup
  useEffect(() => {
    const ws = new WebSocket(`wss://chat.example.com/rooms/${roomId}`);
    wsRef.current = ws;

    ws.onopen = () => setIsConnected(true);
    ws.onclose = () => setIsConnected(false);
    ws.onmessage = (event) => {
      const message = JSON.parse(event.data);
      setMessages(prev => [...prev, message]);
    };

    return () => {
      ws.close();
      wsRef.current = null;
    };
  }, [roomId]);

  // NECESSARY: Scroll to bottom on new messages (DOM manipulation)
  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages]);

  // UNNECESSARY: Resetting state on prop change - use key pattern instead
  useEffect(() => {
    setMessages([]);
    setInputText('');
  }, [roomId]);

  // UNNECESSARY: Event handler logic - should be in handleSend
  const [pendingMessage, setPendingMessage] = useState<string | null>(null);
  useEffect(() => {
    if (pendingMessage && wsRef.current?.readyState === WebSocket.OPEN) {
      wsRef.current.send(JSON.stringify({
        sender: currentUser,
        text: pendingMessage,
        timestamp: Date.now(),
      }));
      setPendingMessage(null);
    }
  }, [pendingMessage, currentUser]);

  function handleSend() {
    if (inputText.trim()) {
      setPendingMessage(inputText);
      setInputText('');
    }
  }

  return (
    <div className="chat-room">
      <div className="status">
        {isConnected ? 'Connected' : 'Disconnected'}
      </div>
      <div className="messages">
        {messages.map(msg => (
          <div key={msg.id} className={msg.sender === currentUser ? 'own' : 'other'}>
            <strong>{msg.sender}</strong>: {msg.text}
          </div>
        ))}
        <div ref={messagesEndRef} />
      </div>
      <div className="input">
        <input
          value={inputText}
          onChange={e => setInputText(e.target.value)}
          onKeyDown={e => e.key === 'Enter' && handleSend()}
          placeholder="Type a message..."
        />
        <button onClick={handleSend} disabled={!isConnected}>Send</button>
      </div>
    </div>
  );
}
