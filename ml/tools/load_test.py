import statistics, time
from fastapi.testclient import TestClient
from service.main import app

CASES = [
    {"text": "Bonjour, on se voit à 10h ?", "urls": []},
    {"text": "Cliquez ici pour vérifier votre compte",
     "urls": ["http://micros0ft-login.com/verify"]},
    {"text": "عاجل: سيتم إيقاف حسابك، أرسل كلمة المرور", "urls": []},
    {"text": "x" * 5000, "urls": []},
]

def main(n=200):
    times = []
    with TestClient(app) as client:
        for i in range(n):
            c = CASES[i % len(CASES)]
            body = {"message_id": f"m{i}", "sender_id": "u_1a", "receiver_id": "u_2b",
                    "conversation_id": "conv_u_1a_u_2b", **c}
            t = time.perf_counter()
            r = client.post("/v1/analyze", json=body)
            times.append((time.perf_counter() - t) * 1000)
            assert r.status_code == 200, r.text
    times.sort()
    print(f"n={n}  moyenne={statistics.mean(times):.1f} ms  "
          f"p50={times[n//2]:.1f}  p95={times[int(n*0.95)]:.1f}  max={times[-1]:.1f}")
    print("OK (< 200 ms)" if times[int(n*0.95)] < 200 else "TROP LENT")

if __name__ == "__main__":
    main()