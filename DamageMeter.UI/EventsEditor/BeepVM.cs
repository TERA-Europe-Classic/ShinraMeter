using System;
using System.Windows.Input;
using Data.Actions.Notify.SoundElements;
using Nostrum;

namespace DamageMeter.UI
{
    public class BeepVM : TSPropertyChanged
    {
        public static event Action<BeepVM> DeleteBeepEvent;

        private readonly Beep _beep;
        private int _frequency;
        private int _duration;

        public int Frequency
        {
            get => _frequency;
            set
            {
                if (_frequency == value) return;
                _frequency = value;
                _beep.Frequency = value;
                NotifyPropertyChanged();
            }
        }

        public int Duration
        {
            get => _duration;
            set
            {
                if (_duration == value) return;
                _duration = value;
                _beep.Duration = value;
                NotifyPropertyChanged();
            }
        }

        public ICommand DeleteBeepCommand { get; }
        public Beep Beep => _beep;

        public BeepVM(Beep beep)
        {
            _beep = beep;
            _frequency = beep.Frequency;
            _duration = beep.Duration;

            DeleteBeepCommand = new RelayCommand(_ => DeleteBeepEvent?.Invoke(this));
        }
    }
}
