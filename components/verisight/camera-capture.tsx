'use client'

import { useEffect, useRef, useState } from 'react'
import { Camera, RefreshCw, X } from 'lucide-react'
import { ActionButton } from './primitives'

type Facing = 'environment' | 'user'

/** Live camera capture: shows the camera, takes one still, hands it back as a JPEG File.
 *  Works on https:// and http://localhost only (browser rule). Rear camera = "environment", front = "user". */
export function CameraCapture({ onCapture, onClose }: { onCapture: (f: File) => void; onClose: () => void }) {
  const videoRef = useRef<HTMLVideoElement>(null)
  const streamRef = useRef<MediaStream | null>(null)
  const [facing, setFacing] = useState<Facing>('environment')
  const [error, setError] = useState<string | null>(null)
  const [ready, setReady] = useState(false)

  function stop() {
    streamRef.current?.getTracks().forEach((t) => t.stop())
    streamRef.current = null
    setReady(false)
  }

  async function start(mode: Facing) {
    stop()
    setError(null)
    if (!navigator.mediaDevices?.getUserMedia) {
      setError('This browser cannot open the camera here. Use https:// or localhost, or upload a file instead.')
      return
    }
    try {
      let stream: MediaStream
      try {
        stream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: { ideal: mode }, width: { ideal: 1920 }, height: { ideal: 1080 } }, audio: false })
      } catch (e) {
        // no rear camera on this device: fall back to whatever camera exists
        if ((e as Error).name === 'OverconstrainedError') stream = await navigator.mediaDevices.getUserMedia({ video: true, audio: false })
        else throw e
      }
      streamRef.current = stream
      if (videoRef.current) {
        videoRef.current.srcObject = stream
        await videoRef.current.play()
      }
      setReady(true)
    } catch (e) {
      const n = (e as Error).name
      setError(
        n === 'NotAllowedError'
          ? 'Camera permission was denied. Allow camera access in the browser and try again.'
          : n === 'NotFoundError'
            ? 'No camera was found on this device.'
            : n === 'NotReadableError'
              ? 'The camera is being used by another app. Close it and try again.'
              : 'Could not start the camera. Upload a file instead.',
      )
    }
  }

  useEffect(() => {
    start(facing)
    return () => stop()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  function capture() {
    const v = videoRef.current
    if (!v || !v.videoWidth) return
    const canvas = document.createElement('canvas')
    canvas.width = v.videoWidth
    canvas.height = v.videoHeight
    canvas.getContext('2d')?.drawImage(v, 0, 0)
    canvas.toBlob(
      (blob) => {
        if (!blob) return setError('Capture failed. Try again.')
        stop()
        onCapture(new File([blob], `camera-capture-${Date.now()}.jpg`, { type: 'image/jpeg' }))
      },
      'image/jpeg',
      0.95,
    )
  }

  function flip() {
    const next: Facing = facing === 'environment' ? 'user' : 'environment'
    setFacing(next)
    start(next)
  }

  function close() {
    stop()
    onClose()
  }

  return (
    <div role="dialog" aria-label="Camera capture" className="flex flex-col gap-3 rounded-md border border-border bg-background/70 p-3">
      <div className="flex items-center justify-between">
        <p className="text-xs uppercase tracking-wider text-muted-foreground">Live camera · {facing === 'environment' ? 'rear' : 'front'}</p>
        <button type="button" onClick={close} className="rounded p-1 text-muted-foreground hover:text-foreground" aria-label="Close camera">
          <X className="size-4" aria-hidden="true" />
        </button>
      </div>
      <div className="relative overflow-hidden rounded-md bg-black">
        <video ref={videoRef} playsInline muted className="aspect-[4/3] w-full object-contain" aria-label="Camera preview" />
        {!ready && !error && <p className="absolute inset-0 flex items-center justify-center text-xs text-muted-foreground">Starting camera…</p>}
      </div>
      {error && <p role="alert" className="rounded-md border border-destructive/40 bg-destructive/10 px-3 py-2 text-xs text-destructive">{error}</p>}
      <p className="text-[11px] text-muted-foreground">Place the card flat, fill the frame, keep it still and well lit. Avoid glare and shadows.</p>
      <div className="flex gap-2">
        <ActionButton className="flex-1" onClick={capture} disabled={!ready}>
          <Camera className="size-4" aria-hidden="true" />
          Capture and verify
        </ActionButton>
        <ActionButton variant="outline" onClick={flip} className="min-h-9 text-xs">
          <RefreshCw className="size-3.5" aria-hidden="true" />
          {facing === 'environment' ? 'Front' : 'Rear'}
        </ActionButton>
      </div>
    </div>
  )
}
