// SKIMMS uplink v2: FreeRTOS task + 20-packet offline buffer. Safety logic (LEDs/buzzer) never waits for the network.
#include <WiFi.h>
#include <HTTPClient.h>
#include <WiFiClientSecure.h>
const char* SSID="YOUR_WIFI"; const char* PASS="YOUR_PASS";
const char* SERVER="http://192.168.1.10:3000/api/telemetry";   // LAN test. Production: https://mine.yourdomain.com/api/telemetry
const char* DEVICE_KEY="PASTE_KEY_FROM_ADMIN_SCREEN";          // board_id in your JSON must equal the registered ESP32 ID
struct Pkt{ char j[460]; };
QueueHandle_t q;
void uplinkTask(void*){
  Pkt p;
  for(;;){
    if(WiFi.status()!=WL_CONNECTED){ WiFi.reconnect(); vTaskDelay(pdMS_TO_TICKS(2000)); continue; }
    if(xQueuePeek(q,&p,pdMS_TO_TICKS(500))!=pdTRUE) continue;
    WiFiClientSecure sc; sc.setInsecure();                      // DEMO ONLY: replace with sc.setCACert(rootCA) in production
    HTTPClient h; bool tls=strncmp(SERVER,"https",5)==0;
    if(tls) h.begin(sc,SERVER); else h.begin(SERVER);
    h.setTimeout(2000); h.addHeader("Content-Type","application/json"); h.addHeader("x-device-key",DEVICE_KEY);
    int code=h.POST((uint8_t*)p.j,strlen(p.j)); h.end();
    if(code==200||code==401||code==403) xQueueReceive(q,&p,0);  // delivered (or rejected): drop it. Other codes: keep and retry
    else vTaskDelay(pdMS_TO_TICKS(1000));
  }
}
void uplinkBegin(){                                             // call once in setup()
  q=xQueueCreate(20,sizeof(Pkt)); WiFi.mode(WIFI_STA); WiFi.begin(SSID,PASS);
  xTaskCreatePinnedToCore(uplinkTask,"uplink",10240,NULL,1,NULL,0);   // core 0; keep sensors/LEDs on core 1 (loop())
}
void uplinkSend(const String& json){                            // call every ~500 ms with your telemetry JSON
  Pkt p; json.toCharArray(p.j,sizeof p.j);
  if(xQueueSend(q,&p,0)!=pdTRUE){ Pkt d; xQueueReceive(q,&d,0); xQueueSend(q,&p,0); }  // buffer full: drop oldest
}
// Optional extra JSON field: "battery":<percent> (shown on the screens). Add a hardware watchdog per your ESP32 core version.
